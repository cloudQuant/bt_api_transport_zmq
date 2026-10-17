# Iteration10 RPC context pool accepted component round

Repository: bt_api_transport_zmq, existing dev; parent ee4cacaee04182fda2d1b9124c2f3a1675aed07b. No worktree. Scope: service_v2.py, test_service_context_pool.py, this record and root-qa.zip.

An explicit process-bound context pool lets clients retain independent DEALER sockets, CURVE credentials and request state while sharing one context. Default standalone clients remain independent. Sockets close before lease release; last-lease termination failures retain retryable custody. Generation checks prevent an old lease from terminating a new context. Server authenticator ownership and all wire limits remain unchanged.

Independent static review: GO_STATIC. Root R1: 32 passed / 1 failed / 1 deselected, 20 Windows Proactor/selector RuntimeWarnings, 6.61 s. The failure was a new test matching cause_code against the exception's generic display string. Only that assertion changed to inspect cause_code and message_id; Root R2 passed that single node in 0.48 s, without warnings. Production bytes stayed identical between both runs. The 32 passing nodes were not repeated. Together this accepts 33 distinct nodes, not a single 33/33 run.

The explicitly deselected legacy-forwarding test references a schema removed by MIG01; it is a known baseline fixture issue, not a pass. The real CURVE test used separate client credentials/principals and established that closing one client leaves the peer usable, followed by normal closure. Remaining focused cases cover default ownership, uncertainty/socket retirement, rollback, termination retry and process/thread boundaries. The static review noted no blocking issue; constructor rollback plus a last-context term failure is not separately exercised.

Both Root runs preserved 106 public source pins and SDK/Base/Transport HEADs. R1's original failure and executed test bytes are preserved in the archive. Current production SHA-256: 0e9ce54895f5295cce72a0a546024da0d4f80efcdb4268c42209da1e817b19ed; current test SHA-256: ef3c1791621f8d185f72962d9bda5f0f8820970ef6c2ff0ff4b2f64cd11da1c6.

Evidence archive: root-qa.zip, 49221 bytes, 23 entries, SHA-256 68871a86dcacbc2408466645470ef004c058f01edd9070aeb6b4918b6f8a6916.

Accepted level: LOCAL_RPC_CONTEXT_POOL_COMPONENT_ONLY. This does not measure memory savings or accept LOAD01, account access or any retained-session action. SDK factory integration is delivered separately after this package commit.
