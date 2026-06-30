# yip-bench Results

Generated: 2026-06-30 17:42:19 UTC

## yip vs kernel WireGuard — netem loss sweep
ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)

| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |
|-----------|-----------|-----------|------------|-----------|
| 0%        | 0%         | 0%         | 18.048      | 10.368     |
| 1%        | 0%         | 2%         | 17.986      | 10.414     |
| 3%        | 0%         | 4%         | 17.909      | 10.378     |
| 5%        | 2%         | 9%         | 17.914      | 10.320     |
| 10%        | 1%         | 20%         | 18.509      | 10.416     |
