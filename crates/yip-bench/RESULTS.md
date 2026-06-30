# yip-bench Results

Generated: 2026-06-30 17:45:46 UTC

## yip vs kernel WireGuard — netem loss sweep
ping -c 100 -i 0.05 -W 1 across each tunnel; netem: loss X% delay 5ms (symmetric)

| injected% | yip_loss% | wg_loss%  | yip_rtt_ms | wg_rtt_ms |
|-----------|-----------|-----------|------------|-----------|
| 0%        | 0%         | 0%         | 17.875      | 10.393     |
| 1%        | 0%         | 0%         | 17.678      | 10.353     |
| 3%        | 0%         | 7%         | 18.000      | 10.397     |
| 5%        | 1%         | 9%         | 18.029      | 10.397     |
| 10%        | 3%         | 12%         | 18.420      | 10.372     |
