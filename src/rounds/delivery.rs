use core::pin::Pin;
use core::sync::atomic::AtomicU64;
use core::task::{ready, Context, Poll};
use std::collections::VecDeque;
use std::sync::Arc;

use gadget_sdk::futures::prelude::*;
use gadget_sdk::network::{self, IdentifierInfo, Network};
use round_based::{Delivery, Incoming, Outgoing};
use round_based::{MessageDestination, MessageType, MsgId, PartyIndex};
use stream::{SplitSink, SplitStream};

pub struct NetworkDeliveryWrapper<N, M> {
    /// The wrapped network implementation.
    network: NetworkWrapper<N, M>,
}

impl<N, M> NetworkDeliveryWrapper<N, M>
where
    N: Network + Unpin,
    M: Clone + Send + Unpin + 'static,
    M: serde::Serialize,
    M: serde::de::DeserializeOwned,
{
    /// Create a new NetworkDeliveryWrapper over a network implementation with the given party index.
    pub fn new(network: N, i: PartyIndex) -> Self {
        let network = NetworkWrapper {
            me: i,
            network,
            outgoing_queue: VecDeque::new(),
            next_msg_id: Arc::new(NextMessageId::default()),
        };
        NetworkDeliveryWrapper { network }
    }
}

/// A NetworkWrapper wraps a network implementation and implements [`Stream`] and [`Sink`] for
/// it.
pub struct NetworkWrapper<N, M> {
    me: PartyIndex,
    network: N,
    outgoing_queue: VecDeque<Outgoing<M>>,
    next_msg_id: Arc<NextMessageId>,
}

impl<N, M> Delivery<M> for NetworkDeliveryWrapper<N, M>
where
    N: Network + Unpin,
    M: Clone + Send + Unpin + 'static,
    M: serde::Serialize + serde::de::DeserializeOwned,
{
    type Send = SplitSink<NetworkWrapper<N, M>, Outgoing<M>>;
    type Receive = SplitStream<NetworkWrapper<N, M>>;
    type SendError = gadget_sdk::Error;
    type ReceiveError = gadget_sdk::Error;

    fn split(self) -> (Self::Receive, Self::Send) {
        let (sink, stream) = self.network.split();
        (stream, sink)
    }
}

impl<N, M> Stream for NetworkWrapper<N, M>
where
    N: Network,
    M: serde::de::DeserializeOwned,
{
    type Item = Result<Incoming<M>, gadget_sdk::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let p = self.network.next_message().poll_unpin(cx);
            let m = match ready!(p) {
                Some(msg) => msg,
                None => return Poll::Ready(None),
            };
            let msg = network::deserialize::<M>(&m.payload)
                .map(|msg| Incoming {
                    id: self.next_msg_id.next(),
                    sender: m.sender.user_id,
                    msg_type: match m.recipient {
                        Some(_) => MessageType::P2P,
                        None => MessageType::Broadcast,
                    },
                    msg,
                })
                .map_err(gadget_sdk::Error::from);
            return Poll::Ready(Some(msg));
        }
    }
}

impl<N, M> Sink<Outgoing<M>> for NetworkWrapper<N, M>
where
    N: Network + Unpin,
    M: Unpin + serde::Serialize,
{
    type Error = gadget_sdk::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, msg: Outgoing<M>) -> Result<(), Self::Error> {
        self.get_mut().outgoing_queue.push_back(msg);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        // Dequeue all messages and send them one by one to the network
        let this = self.get_mut();
        while let Some(out) = this.outgoing_queue.pop_front() {
            // TODO: Set the correct identifier info from the network.
            let identifier_info = IdentifierInfo {
                block_id: None,
                session_id: None,
                retry_id: None,
                task_id: None,
            };
            let to = match out.recipient {
                MessageDestination::AllParties => None,
                MessageDestination::OneParty(p) => Some(p),
            };
            let protocol_message =
                N::build_protocol_message(identifier_info, this.me, to, &out.msg, None, None);
            let p = this.network.send_message(protocol_message).poll_unpin(cx);
            match ready!(p) {
                Ok(()) => continue,
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct NextMessageId(AtomicU64);

impl NextMessageId {
    pub fn next(&self) -> MsgId {
        self.0.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    }
}
