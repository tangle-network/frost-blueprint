use std::{
    error, fmt, io, iter,
    net::{Ipv4Addr, Ipv6Addr},
    ops::DerefMut,
    pin::Pin,
    str,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{future::BoxFuture, prelude::*};
use hickory_resolver::{ConnectionProvider, lookup::Lookup, lookup_ip::LookupIp, proto::rr::RData};
pub use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    net::NetError as ResolveError,
};
use libp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{DialOpts, ListenerId, TransportError, TransportEvent},
};
use parking_lot::Mutex;
use smallvec::SmallVec;

/// The prefix for `dnsaddr` protocol TXT record lookups.
const DNSADDR_PREFIX: &str = "_dnsaddr.";

/// The maximum number of dialing attempts to resolved addresses.
const MAX_DIAL_ATTEMPTS: usize = 16;

/// The maximum number of DNS lookups when dialing.
///
/// This limit is primarily a safeguard against too many, possibly
/// even cyclic, indirections in the addresses obtained from the
/// TXT records of a `/dnsaddr`.
const MAX_DNS_LOOKUPS: usize = 32;

/// The maximum number of TXT records applicable for the address
/// being dialed that are considered for further lookups as a
/// result of a single `/dnsaddr` lookup.
const MAX_TXT_RECORDS: usize = 16;

/// A [`Transport`] for performing DNS lookups when dialing `Multiaddr`esses.
/// You shouldn't need to use this type directly. Use [`tokio::Transport`] instead.
#[derive(Debug)]
pub struct Transport<T, R> {
    /// The underlying transport.
    pub(crate) inner: Arc<Mutex<T>>,
    /// The DNS resolver used when dialing addresses with DNS components.
    pub(crate) resolver: R,
}

impl<T, R> libp2p_core::Transport for Transport<T, R>
where
    T: libp2p_core::Transport + Send + Unpin + 'static,
    T::Error: Send,
    T::Dial: Send,
    R: Clone + Send + Sync + Resolver + 'static,
{
    type Output = T::Output;
    type Error = Error<T::Error>;
    type ListenerUpgrade = future::MapErr<T::ListenerUpgrade, fn(T::Error) -> Self::Error>;
    type Dial = future::Either<
        future::MapErr<T::Dial, fn(T::Error) -> Self::Error>,
        BoxFuture<'static, Result<Self::Output, Self::Error>>,
    >;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner
            .lock()
            .listen_on(id, addr)
            .map_err(|e| e.map(Error::Transport))
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.lock().remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        dial_opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        Ok(self.do_dial(addr, dial_opts))
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let mut inner = self.inner.lock();
        libp2p_core::Transport::poll(Pin::new(inner.deref_mut()), cx).map(|event| {
            event
                .map_upgrade(|upgr| upgr.map_err::<_, fn(_) -> _>(Error::Transport))
                .map_err(Error::Transport)
        })
    }
}

impl<T, R> Transport<T, R>
where
    T: libp2p_core::Transport + Send + Unpin + 'static,
    T::Error: Send,
    T::Dial: Send,
    R: Clone + Send + Sync + Resolver + 'static,
{
    fn do_dial(
        &mut self,
        addr: Multiaddr,
        dial_opts: DialOpts,
    ) -> <Self as libp2p_core::Transport>::Dial {
        let resolver = self.resolver.clone();
        let inner = self.inner.clone();

        // Asynchronously resolve all DNS names in the address before proceeding
        // with dialing on the underlying transport.
        async move {
            let mut dial_errors: Vec<Error<T::Error>> = Vec::new();
            let mut dns_lookups = 0;
            let mut dial_attempts = 0;
            // We optimise for the common case of a single DNS component
            // in the address that is resolved with a single lookup.
            let mut unresolved = SmallVec::<[Multiaddr; 1]>::new();
            unresolved.push(addr.clone());

            // Resolve (i.e. replace) all DNS protocol components, initiating
            // dialing attempts as soon as there is another fully resolved
            // address.
            while let Some(addr) = unresolved.pop() {
                if let Some((i, name)) = addr.iter().enumerate().find(|(_, p)| {
                    matches!(
                        p,
                        Protocol::Dns(_)
                            | Protocol::Dns4(_)
                            | Protocol::Dns6(_)
                            | Protocol::Dnsaddr(_)
                    )
                }) {
                    if dns_lookups == MAX_DNS_LOOKUPS {
                        tracing::debug!(address=%addr, "Too many DNS lookups, dropping unresolved address");
                        dial_errors.push(Error::TooManyLookups);
                        // There may still be fully resolved addresses in `unresolved`,
                        // so keep going until `unresolved` is empty.
                        continue;
                    }
                    dns_lookups += 1;
                    match resolve(&name, &resolver).await {
                        Err(e) => {
                            // Record the resolution error.
                            dial_errors.push(e);
                        }
                        Ok(Resolved::One(ip)) => {
                            tracing::trace!(protocol=%name, resolved=%ip);
                            let addr = addr.replace(i, |_| Some(ip)).expect("`i` is a valid index");
                            unresolved.push(addr);
                        }
                        Ok(Resolved::Many(ips)) => {
                            for ip in ips {
                                tracing::trace!(protocol=%name, resolved=%ip);
                                let addr =
                                    addr.replace(i, |_| Some(ip)).expect("`i` is a valid index");
                                unresolved.push(addr);
                            }
                        }
                        Ok(Resolved::Addrs(addrs)) => {
                            let suffix = addr.iter().skip(i + 1).collect::<Multiaddr>();
                            let prefix = addr.iter().take(i).collect::<Multiaddr>();
                            let mut n = 0;
                            for a in addrs {
                                if a.ends_with(&suffix) {
                                    if n < MAX_TXT_RECORDS {
                                        n += 1;
                                        tracing::trace!(protocol=%name, resolved=%a);
                                        let addr =
                                            prefix.iter().chain(a.iter()).collect::<Multiaddr>();
                                        unresolved.push(addr);
                                    } else {
                                        tracing::debug!(
                                            resolved=%a,
                                            "Too many TXT records, dropping resolved"
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // We have a fully resolved address, so try to dial it.
                    tracing::debug!(address=%addr, "Dialing address");

                    let transport = inner.clone();
                    let dial = transport.lock().dial(addr, dial_opts);
                    let result = match dial {
                        Ok(out) => {
                            // We only count attempts that the inner transport
                            // actually accepted, i.e. for which it produced
                            // a dialing future.
                            dial_attempts += 1;
                            out.await.map_err(Error::Transport)
                        }
                        Err(TransportError::MultiaddrNotSupported(a)) => {
                            Err(Error::MultiaddrNotSupported(a))
                        }
                        Err(TransportError::Other(err)) => Err(Error::Transport(err)),
                    };

                    match result {
                        Ok(out) => return Ok(out),
                        Err(err) => {
                            tracing::debug!("Dial error: {:?}.", err);
                            dial_errors.push(err);

                            if unresolved.is_empty() {
                                break;
                            }

                            if dial_attempts == MAX_DIAL_ATTEMPTS {
                                tracing::debug!(
                                    "Aborting dialing after {} attempts.",
                                    MAX_DIAL_ATTEMPTS
                                );
                                break;
                            }
                        }
                    }
                }
            }

            // If we have any dial errors, aggregate them.
            // Otherwise there were no valid DNS records for the given address to begin with
            // (i.e. DNS lookups succeeded but produced no records relevant for the given `addr`).
            if !dial_errors.is_empty() {
                Err(Error::Dial(dial_errors))
            } else {
                Err(Error::ResolveError(
                    ResolveError::from("No Matching Records Found"),
                ))
            }
        }
        .boxed()
        .right_future()
    }
}

/// The possible errors of a [`Transport`] wrapped transport.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error<TErr> {
    /// The underlying transport encountered an error.
    Transport(TErr),
    /// DNS resolution failed.
    #[allow(clippy::enum_variant_names)]
    ResolveError(ResolveError),
    /// DNS resolution was successful, but the underlying transport refused the resolved address.
    MultiaddrNotSupported(Multiaddr),
    /// DNS resolution involved too many lookups.
    ///
    /// DNS resolution on dialing performs up to 32 DNS lookups. If these
    /// are not sufficient to obtain a fully-resolved address, this error
    /// is returned and the DNS records for the domain(s) being dialed
    /// should be investigated.
    TooManyLookups,
    /// Multiple dial errors were encountered.
    Dial(Vec<Error<TErr>>),
}

impl<TErr> fmt::Display for Error<TErr>
where
    TErr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(err) => write!(f, "{err}"),
            Error::ResolveError(err) => write!(f, "{err}"),
            Error::MultiaddrNotSupported(a) => write!(f, "Unsupported resolved address: {a}"),
            Error::TooManyLookups => write!(f, "Too many DNS lookups"),
            Error::Dial(errs) => {
                write!(f, "Multiple dial errors occurred:")?;
                for err in errs {
                    write!(f, "\n - {err}")?;
                }
                Ok(())
            }
        }
    }
}

impl<TErr> error::Error for Error<TErr>
where
    TErr: error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Transport(err) => Some(err),
            Error::ResolveError(err) => Some(err),
            Error::MultiaddrNotSupported(_) => None,
            Error::TooManyLookups => None,
            Error::Dial(errs) => errs.last().and_then(|e| e.source()),
        }
    }
}

/// The successful outcome of [`resolve`] for a given [`Protocol`].
enum Resolved<'a> {
    /// The given `Protocol` has been resolved to a single `Protocol`,
    /// which may be identical to the one given, in case it is not
    /// a DNS protocol component.
    One(Protocol<'a>),
    /// The given `Protocol` has been resolved to multiple alternative
    /// `Protocol`s as a result of a DNS lookup.
    Many(Vec<Protocol<'a>>),
    /// The given `Protocol` has been resolved to a new list of `Multiaddr`s
    /// obtained from DNS TXT records representing possible alternatives.
    /// These addresses may contain further DNS names that need resolving.
    Addrs(Vec<Multiaddr>),
}

/// Asynchronously resolves the domain name of a `Dns`, `Dns4`, `Dns6` or `Dnsaddr` protocol
/// component. If the given protocol is of a different type, it is returned unchanged as a
/// [`Resolved::One`].
fn resolve<'a, E: 'a + Send, R: Resolver>(
    proto: &Protocol<'a>,
    resolver: &'a R,
) -> BoxFuture<'a, Result<Resolved<'a>, Error<E>>> {
    match proto {
        Protocol::Dns(name) => resolver
            .lookup_ip(name.clone().into_owned())
            .map(move |res| match res {
                Ok(ips) => {
                    let mut ips = ips.iter();
                    let one = ips
                        .next()
                        .expect("If there are no results, `Err(NoRecordsFound)` is expected.");
                    if let Some(two) = ips.next() {
                        Ok(Resolved::Many(
                            iter::once(one)
                                .chain(iter::once(two))
                                .chain(ips)
                                .map(Protocol::from)
                                .collect(),
                        ))
                    } else {
                        Ok(Resolved::One(Protocol::from(one)))
                    }
                }
                Err(e) => Err(Error::ResolveError(e)),
            })
            .boxed(),
        Protocol::Dns4(name) => resolver
            .ipv4_lookup(name.clone().into_owned())
            .map(move |res| match res {
                Ok(ips) => {
                    let mut ips = ips
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::A(ip) => Some(Ipv4Addr::from(*ip)),
                            _ => None,
                        });
                    let one = ips
                        .next()
                        .expect("If there are no results, `Err(NoRecordsFound)` is expected.");
                    if let Some(two) = ips.next() {
                        Ok(Resolved::Many(
                            iter::once(one)
                                .chain(iter::once(two))
                                .chain(ips)
                                .map(Protocol::from)
                                .collect(),
                        ))
                    } else {
                        Ok(Resolved::One(Protocol::from(one)))
                    }
                }
                Err(e) => Err(Error::ResolveError(e)),
            })
            .boxed(),
        Protocol::Dns6(name) => resolver
            .ipv6_lookup(name.clone().into_owned())
            .map(move |res| match res {
                Ok(ips) => {
                    let mut ips = ips
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            RData::AAAA(ip) => Some(Ipv6Addr::from(*ip)),
                            _ => None,
                        });
                    let one = ips
                        .next()
                        .expect("If there are no results, `Err(NoRecordsFound)` is expected.");
                    if let Some(two) = ips.next() {
                        Ok(Resolved::Many(
                            iter::once(one)
                                .chain(iter::once(two))
                                .chain(ips)
                                .map(Protocol::from)
                                .collect(),
                        ))
                    } else {
                        Ok(Resolved::One(Protocol::from(one)))
                    }
                }
                Err(e) => Err(Error::ResolveError(e)),
            })
            .boxed(),
        Protocol::Dnsaddr(name) => {
            let name = [DNSADDR_PREFIX, name].concat();
            resolver
                .txt_lookup(name)
                .map(move |res| match res {
                    Ok(txts) => {
                        let mut addrs = Vec::new();
                        for txt in txts
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::TXT(txt) => Some(txt),
                                _ => None,
                            })
                        {
                            if let Some(chars) = txt.txt_data.first() {
                                match parse_dnsaddr_txt(chars) {
                                    Err(e) => {
                                        // Skip over seemingly invalid entries.
                                        tracing::debug!("Invalid TXT record: {:?}", e);
                                    }
                                    Ok(a) => {
                                        addrs.push(a);
                                    }
                                }
                            }
                        }
                        Ok(Resolved::Addrs(addrs))
                    }
                    Err(e) => Err(Error::ResolveError(e)),
                })
                .boxed()
        }
        proto => future::ready(Ok(Resolved::One(proto.clone()))).boxed(),
    }
}

/// Parses a `<character-string>` of a `dnsaddr` TXT record.
fn parse_dnsaddr_txt(txt: &[u8]) -> io::Result<Multiaddr> {
    let s = str::from_utf8(txt).map_err(invalid_data)?;
    match s.strip_prefix("dnsaddr=") {
        None => Err(invalid_data("Missing `dnsaddr=` prefix.")),
        Some(a) => Ok(Multiaddr::try_from(a).map_err(invalid_data)?),
    }
}

fn invalid_data(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[doc(hidden)]
pub trait Resolver {
    fn lookup_ip(
        &self,
        name: String,
    ) -> impl Future<Output = Result<LookupIp, ResolveError>> + Send;
    fn ipv4_lookup(
        &self,
        name: String,
    ) -> impl Future<Output = Result<Lookup, ResolveError>> + Send;
    fn ipv6_lookup(
        &self,
        name: String,
    ) -> impl Future<Output = Result<Lookup, ResolveError>> + Send;
    fn txt_lookup(&self, name: String)
    -> impl Future<Output = Result<Lookup, ResolveError>> + Send;
}

impl<C> Resolver for hickory_resolver::Resolver<C>
where
    C: ConnectionProvider,
{
    async fn lookup_ip(&self, name: String) -> Result<LookupIp, ResolveError> {
        self.lookup_ip(name).await
    }

    async fn ipv4_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.ipv4_lookup(name).await
    }

    async fn ipv6_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.ipv6_lookup(name).await
    }

    async fn txt_lookup(&self, name: String) -> Result<Lookup, ResolveError> {
        self.txt_lookup(name).await
    }
}
