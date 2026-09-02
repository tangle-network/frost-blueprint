    use futures::future::BoxFuture;
    use hickory_resolver::config::QUAD9;
    use libp2p_core::{
        Endpoint, Transport,
        multiaddr::{Multiaddr, Protocol},
        transport::{PortUse, TransportError, TransportEvent},
    };
    use libp2p_identity::PeerId;

    use super::*;

    fn test_tokio<T, F: Future<Output = ()>>(
        transport: T,
        test_fn: impl FnOnce(tokio::Transport<T>) -> F,
    ) {
        let config = ResolverConfig::udp_and_tcp(&QUAD9);
        let opts = ResolverOpts::default();
        let transport = tokio::Transport::custom(transport, config, opts);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(test_fn(transport));
    }

    #[test]
    fn basic_resolve() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        #[derive(Clone)]
        struct CustomTransport;

        impl Transport for CustomTransport {
            type Output = ();
            type Error = std::io::Error;
            type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;
            type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

            fn listen_on(
                &mut self,
                _: ListenerId,
                _: Multiaddr,
            ) -> Result<(), TransportError<Self::Error>> {
                unreachable!()
            }

            fn remove_listener(&mut self, _: ListenerId) -> bool {
                false
            }

            fn dial(
                &mut self,
                addr: Multiaddr,
                _: DialOpts,
            ) -> Result<Self::Dial, TransportError<Self::Error>> {
                // Check that all DNS components have been resolved, i.e. replaced.
                assert!(!addr.iter().any(|p| matches!(
                    p,
                    Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
                )));
                Ok(Box::pin(future::ready(Ok(()))))
            }

            fn poll(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
                unreachable!()
            }
        }

        async fn run<T, R>(mut transport: super::Transport<T, R>)
        where
            T: Transport + Clone + Send + Unpin + 'static,
            T::Error: Send,
            T::Dial: Send,
            R: Clone + Send + Sync + Resolver + 'static,
        {
            let dial_opts = DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };

            // Success due to existing A record for example.com.
            let _ = transport
                .dial("/dns4/example.com/tcp/20000".parse().unwrap(), dial_opts)
                .unwrap()
                .await
                .unwrap();

            // Success due to existing AAAA record for example.com.
            let _ = transport
                .dial("/dns6/example.com/tcp/20000".parse().unwrap(), dial_opts)
                .unwrap()
                .await
                .unwrap();

            // Success due to pass-through, i.e. nothing to resolve.
            let _ = transport
                .dial("/ip4/1.2.3.4/tcp/20000".parse().unwrap(), dial_opts)
                .unwrap()
                .await
                .unwrap();

            // Success due to the DNS TXT records at _dnsaddr.bootstrap.libp2p.io.
            let _ = transport
                .dial("/dnsaddr/bootstrap.libp2p.io".parse().unwrap(), dial_opts)
                .unwrap()
                .await
                .unwrap();

            // Success due to the DNS TXT records at _dnsaddr.bootstrap.libp2p.io having
            // an entry with suffix `/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN`,
            // i.e. a bootnode with such a peer ID.
            let _ = transport
                .dial("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN".parse().unwrap(), dial_opts)
                .unwrap()
                .await
                .unwrap();

            // Failure due to the DNS TXT records at _dnsaddr.libp2p.io not having
            // an entry with a random `p2p` suffix.
            match transport
                .dial(
                    format!("/dnsaddr/bootstrap.libp2p.io/p2p/{}", PeerId::random())
                        .parse()
                        .unwrap(),
                    dial_opts,
                )
                .unwrap()
                .await
            {
                Err(Error::ResolveError(_)) => {}
                Err(e) => panic!("Unexpected error: {e:?}"),
                Ok(_) => panic!("Unexpected success."),
            }

            // Failure due to no records.
            match transport
                .dial(
                    "/dns4/example.invalid/tcp/20000".parse().unwrap(),
                    dial_opts,
                )
                .unwrap()
                .await
            {
                Err(Error::Dial(dial_errs)) => {
                    assert_eq!(
                        dial_errs.len(),
                        1,
                        "Expected exactly 1 error for 'no records' scenario, got {dial_errs:?}"
                    );

                    match &dial_errs[0] {
                        Error::ResolveError(e) if e.is_no_records_found() => {}
                        Error::ResolveError(e) => panic!("Unexpected DNS error: {e:?}"),
                        other => {
                            panic!("Expected a single ResolveError(...) sub-error, got {other:?}")
                        }
                    }
                }

                Err(e) => panic!("Unexpected error: {e:?}"),
                Ok(_) => panic!("Unexpected success."),
            }
        }

        test_tokio(CustomTransport, run);
    }

    #[test]
    fn aggregated_dial_errors() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        #[derive(Clone)]
        struct AlwaysFailTransport;

        impl libp2p_core::Transport for AlwaysFailTransport {
            type Output = ();
            type Error = std::io::Error;
            type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;
            type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

            fn listen_on(
                &mut self,
                _id: ListenerId,
                _addr: Multiaddr,
            ) -> Result<(), TransportError<Self::Error>> {
                unimplemented!()
            }

            fn remove_listener(&mut self, _id: ListenerId) -> bool {
                false
            }

            fn dial(
                &mut self,
                addr: Multiaddr,
                _: DialOpts,
            ) -> Result<Self::Dial, TransportError<Self::Error>> {
                // Every dial attempt fails with an error that includes the address.
                Ok(Box::pin(future::ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("No support for dialing {addr}"),
                )))))
            }

            fn poll(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
                unimplemented!()
            }
        }

        async fn run_test<T, R>(mut transport: super::Transport<T, R>)
        where
            T: Transport<Error = std::io::Error> + Clone + Send + Unpin + 'static,
            T::Error: Send,
            T::Dial: Send,
            R: Clone + Send + Sync + Resolver + 'static,
        {
            let dial_opts = DialOpts {
                role: Endpoint::Dialer,
                port_use: PortUse::Reuse,
            };

            // This address requires DNS resolution, yielding two IP addresses,
            // forcing two dial attempts. Both fail.
            let addr: Multiaddr = "/dnsaddr/bootstrap.libp2p.io".parse().unwrap();
            let dial_future = transport.dial(addr, dial_opts).unwrap();
            let result = dial_future.await;

            match result {
                Err(Error::Dial(errs)) => {
                    // We expect at least 2 errors, one per resolved IP.
                    assert!(
                        errs.len() >= 2,
                        "Expected multiple dial errors, but got {}",
                        errs.len()
                    );
                    for e in errs {
                        match e {
                            Error::Transport(io_err) => {
                                assert_eq!(
                                    io_err.kind(),
                                    io::ErrorKind::Unsupported,
                                    "Expected Unsupported dial error, got: {io_err:?}"
                                );
                            }
                            _ => panic!("Expected Error::Transport(Unsupported), got: {e:?}"),
                        }
                    }
                }
                Err(e) => panic!("Expected aggregated dial errors, got {e:?}"),
                Ok(_) => panic!("Dial unexpectedly succeeded"),
            }
        }

        test_tokio(AlwaysFailTransport, run_test);
    }
