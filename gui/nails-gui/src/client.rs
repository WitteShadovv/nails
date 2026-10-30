// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's end of the protocol (see [`nails_api::protocol`]).
//!
//! A [`Client`] holds one session with the engine's helper. It opens with the
//! handshake: the helper speaks first, and the window answers only a helper of
//! its own release and protocol ([`ours`]); a helper of any other is refused
//! before the window sends anything, and the session ends. Then it sends one
//! request at a time and reads every frame up to that request's answer,
//! passing the request's events on as they come.
//!
//! An operation the engine confirms first runs as a [`Plan`] and its apply.
//! The plan's answer carries the data the window shows before it asks, and a
//! single-use token; [`Client::apply`] sends that token back. The helper
//! withdraws a plan as soon as any other request comes, so the client refuses
//! to apply a plan once another request was sent, without asking the helper.

use std::io::Write;
use std::os::unix::net::UnixStream;

use nails_api::Event;
use nails_api::protocol::{
    ActivateArgs, ActivatePlanData, DeactivateArgs, DeactivatePlanData, DiscardPlanArgs,
    DiscardPlanData, ErrorCode, Frame, Hello, InitArgs, InitPlanData, Op, PROTOCOL_VERSION,
    ProtocolError, RELEASE, Request, Token,
};

use crate::frames::{FrameError, FrameReader};

/// The window's own versions, as its hello names them: this protocol and the
/// release of the engine it was built with.
#[must_use]
pub fn ours() -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        engine: RELEASE.to_string(),
    }
}

/// How a request was answered: the exit code and the envelope the CLI gives
/// for the same command under `--json`.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The exit code the CLI exits with for this outcome.
    pub exit: u8,
    /// The envelope, as the CLI prints it.
    pub envelope: serde_json::Value,
}

/// Why a session cannot go on, or a request was not answered.
#[derive(Debug)]
pub enum ClientError {
    /// The helper is of another release or protocol. Nothing was sent.
    Mismatch {
        /// The window's versions.
        window: Hello,
        /// The helper's versions, from its hello.
        engine: Hello,
    },
    /// The helper refused a request. Only a refused token leaves the session
    /// open; every other refusal ended it.
    Refused(ProtocolError),
    /// The helper closed its end of the pipe.
    Closed,
    /// The pipe failed or carried something the protocol does not allow.
    Broken(String),
    /// The plan was withdrawn: another request was sent after it.
    PlanWithdrawn,
}

impl ClientError {
    /// Whether the session is over after this error.
    #[must_use]
    pub fn ends_session(&self) -> bool {
        match self {
            ClientError::Refused(error) => error.code != ErrorCode::BadToken,
            ClientError::PlanWithdrawn => false,
            ClientError::Mismatch { .. } | ClientError::Closed | ClientError::Broken(_) => true,
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(error: FrameError) -> Self {
        ClientError::Broken(error.to_string())
    }
}

/// An operation the engine runs in two requests: this plan, then its apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// `nails discard`.
    Discard(DiscardPlanArgs),
    /// `nails activate`.
    Activate(ActivateArgs),
    /// `nails deactivate`.
    Deactivate(DeactivateArgs),
    /// `nails init`.
    Init(InitArgs),
}

impl Plan {
    fn op(self) -> Op {
        match self {
            Plan::Discard(args) => Op::DiscardPlan(args),
            Plan::Activate(args) => Op::ActivatePlan(args),
            Plan::Deactivate(args) => Op::DeactivatePlan(args),
            Plan::Init(args) => Op::InitPlan(args),
        }
    }

    /// The plan data of `data`, the `data` of a plan answer that holds a
    /// token, read as this kind of plan.
    fn data(&self, data: serde_json::Value) -> Result<PlanData, serde_json::Error> {
        Ok(match self {
            Plan::Discard(_) => PlanData::Discard(serde_json::from_value(data)?),
            Plan::Activate(_) => PlanData::Activate(serde_json::from_value(data)?),
            Plan::Deactivate(_) => PlanData::Deactivate(serde_json::from_value(data)?),
            Plan::Init(_) => PlanData::Init(serde_json::from_value(data)?),
        })
    }
}

/// What a plan says its apply would do, as the engine's plan answer carries
/// it, token included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanData {
    /// What a discard would delete.
    Discard(DiscardPlanData),
    /// What an activation past its gates would say before it asks.
    Activate(ActivatePlanData),
    /// What a deactivation would not put back.
    Deactivate(DeactivatePlanData),
    /// The layout an init would write.
    Init(InitPlanData),
}

impl PlanData {
    fn token(&self) -> &str {
        match self {
            PlanData::Discard(data) => &data.token,
            PlanData::Activate(data) => &data.token,
            PlanData::Deactivate(data) => &data.token,
            PlanData::Init(data) => &data.token,
        }
    }

    fn apply_op(&self) -> Op {
        let token = Token {
            token: self.token().to_string(),
        };
        match self {
            PlanData::Discard(_) => Op::DiscardApply(token),
            PlanData::Activate(_) => Op::ActivateApply(token),
            PlanData::Deactivate(_) => Op::DeactivateApply(token),
            PlanData::Init(_) => Op::InitApply(token),
        }
    }
}

/// A plan the helper holds for its apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    data: PlanData,
    /// The number of the plan request, which must be the last request sent
    /// when the apply goes out.
    request: u64,
}

impl Planned {
    /// What the apply would do.
    #[must_use]
    pub fn data(&self) -> &PlanData {
        &self.data
    }
}

/// How the engine answered a plan.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanAnswer {
    /// The plan holds; its apply may follow.
    Ready(Planned),
    /// There is nothing to apply: the answer is the CLI's envelope for the
    /// operation (it was refused, or there is nothing to do), with no token.
    Settled(Answer),
}

/// One session with the engine's helper.
pub struct Client {
    frames: FrameReader<UnixStream>,
    output: UnixStream,
    engine: Hello,
    next_id: u64,
    last_request: u64,
    ended: bool,
}

impl Client {
    /// Open a session on `stream`, one end of the helper's pipe: read the
    /// helper's hello, refuse a helper of another release or protocol, and
    /// send the window's hello.
    ///
    /// # Errors
    ///
    /// [`ClientError::Mismatch`] for a helper of another release or protocol
    /// (nothing was sent to it), [`ClientError::Refused`] when the helper
    /// refused the window's hello, [`ClientError::Closed`] when it closed the
    /// pipe first, and [`ClientError::Broken`] for a failed pipe or a frame
    /// out of place.
    pub fn connect(stream: UnixStream) -> Result<Self, ClientError> {
        let output = stream
            .try_clone()
            .map_err(|error| ClientError::Broken(format!("the pipe failed: {error}")))?;
        let mut frames = FrameReader::new(stream);
        let engine = match frames.next_frame()? {
            Some(Frame::Hello(engine)) => engine,
            Some(other) => {
                return Err(ClientError::Broken(format!(
                    "the helper did not open with its hello: {}",
                    other.to_line()
                )));
            }
            None => return Err(ClientError::Closed),
        };
        let window = ours();
        if engine != window {
            return Err(ClientError::Mismatch { window, engine });
        }
        let mut client = Self {
            frames,
            output,
            engine,
            next_id: 1,
            last_request: 0,
            ended: false,
        };
        let answer = client.request(Op::Hello(ours()), &mut |_| {})?;
        if answer.exit != 0
            || answer.envelope["data"] != serde_json::to_value(ours()).unwrap_or_default()
        {
            client.ended = true;
            return Err(ClientError::Broken(format!(
                "the helper answered the hello with {}",
                answer.envelope
            )));
        }
        Ok(client)
    }

    /// The helper's versions, from its hello.
    #[must_use]
    pub fn engine(&self) -> &Hello {
        &self.engine
    }

    /// Another handle on the window's end of the pipe, for
    /// [`crate::worker::HangUp`]: once its writing half is shut, the helper
    /// reads the window as gone.
    ///
    /// # Errors
    ///
    /// The error of duplicating the descriptor.
    pub fn hang_up_handle(&self) -> std::io::Result<UnixStream> {
        self.output.try_clone()
    }

    /// Run `op` and return its answer, passing each event of it to
    /// `on_event` as it comes. A plan goes through [`Client::plan`] instead,
    /// and an apply through [`Client::apply`].
    ///
    /// # Errors
    ///
    /// Any [`ClientError`] but [`ClientError::Mismatch`]; after one that
    /// [ends the session](ClientError::ends_session), every later call
    /// returns [`ClientError::Closed`].
    pub fn call(&mut self, op: Op, on_event: &mut dyn FnMut(Event)) -> Result<Answer, ClientError> {
        if matches!(op, Op::Hello(_)) || op.apply_token().is_some() || is_plan(&op) {
            // A bug of the window, not of the helper: the session cannot be
            // trusted to be in step any more.
            self.ended = true;
            return Err(ClientError::Broken(format!(
                "{} is not a request of its own",
                op.name()
            )));
        }
        self.request(op, on_event)
    }

    /// Ask for `plan`: what its apply would do, and the token for it.
    ///
    /// # Errors
    ///
    /// As [`Client::call`], and [`ClientError::Broken`] for a plan answer
    /// with a token whose data is not that plan's.
    pub fn plan(
        &mut self,
        plan: Plan,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<PlanAnswer, ClientError> {
        let answer = self.request(plan.clone().op(), on_event)?;
        let token = answer.envelope["data"]["token"].is_string();
        if answer.exit != 0 || answer.envelope["ok"] != true || !token {
            return Ok(PlanAnswer::Settled(answer));
        }
        let data = plan
            .data(answer.envelope["data"].clone())
            .map_err(|error| {
                self.ended = true;
                ClientError::Broken(format!("a plan answer the window cannot read: {error}"))
            })?;
        Ok(PlanAnswer::Ready(Planned {
            data,
            request: self.last_request,
        }))
    }

    /// Apply `planned`, passing each event of it to `on_event` as it comes.
    ///
    /// # Errors
    ///
    /// [`ClientError::PlanWithdrawn`], without asking the helper, when another
    /// request was sent after the plan; otherwise as [`Client::call`].
    pub fn apply(
        &mut self,
        planned: Planned,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<Answer, ClientError> {
        if self.ended {
            return Err(ClientError::Closed);
        }
        if planned.request != self.last_request {
            return Err(ClientError::PlanWithdrawn);
        }
        self.request(planned.data.apply_op(), on_event)
    }

    /// Send `op` as the next request and read every frame up to its answer.
    fn request(&mut self, op: Op, on_event: &mut dyn FnMut(Event)) -> Result<Answer, ClientError> {
        if self.ended {
            return Err(ClientError::Closed);
        }
        let result = self.exchange(op, on_event);
        if let Err(error) = &result
            && error.ends_session()
        {
            self.ended = true;
        }
        result
    }

    fn exchange(&mut self, op: Op, on_event: &mut dyn FnMut(Event)) -> Result<Answer, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        self.last_request = id;
        let mut line = Request {
            v: PROTOCOL_VERSION,
            id,
            op,
        }
        .to_line();
        line.push('\n');
        self.output
            .write_all(line.as_bytes())
            .and_then(|()| self.output.flush())
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::BrokenPipe => ClientError::Closed,
                _ => ClientError::Broken(format!("the pipe failed: {error}")),
            })?;
        loop {
            match self.frames.next_frame()? {
                None => return Err(ClientError::Closed),
                Some(Frame::Event { id: of, event }) if of == id => on_event(event),
                Some(Frame::Result {
                    id: of,
                    exit,
                    envelope,
                }) if of == id => {
                    return Ok(Answer { exit, envelope });
                }
                Some(Frame::Error { id: of, error }) if of.is_none_or(|of| of == id) => {
                    return Err(ClientError::Refused(error));
                }
                Some(other) => {
                    return Err(ClientError::Broken(format!(
                        "a frame out of place while request {id} ran: {}",
                        other.to_line()
                    )));
                }
            }
        }
    }
}

fn is_plan(op: &Op) -> bool {
    matches!(
        op,
        Op::DiscardPlan(_) | Op::ActivatePlan(_) | Op::DeactivatePlan(_) | Op::InitPlan(_)
    )
}
