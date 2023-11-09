# Changelog CN 1.14

## 1.14.0

Antrea[1]项目是一个基于Open vSwitch（OVS）的开源Kubernetes CNI网络解决方案，旨在为Kubernetes集群提供更高效、更安全的跨平台网络和安全策略。
2023年10月28日，Antrea发布了最新版本v1.14.0[2]，Theia v0.8.0[3]也已经同步发布！
Antrea v1.14.0的发布非常值得关注，首先AntreaProxy、NodePortLocal和EndpointSlice这三个关键特性升级至GA版本，其可靠性在生产实践中得到测试验证，显示了我们致力于为Kubernetes提供强大可靠的网络解决方案的决心。其次，此次发布还包含了许多亮眼的功能增强，例如Egress实现了QoS，用户现在可以通过Egress API指定和控制其应用的Pod的南北向出口流量的速率，实现网络资源的高效利用和服务质量管理。同时为Egress新增多个状态字段以提升其可见行，从而更容易监控和定位相关问题。最后，此次发布还引入了将Pod的secondary interface接入VLAN网络的能力，确保一些扩展用例中的应用获得最佳性能和网络隔离。Antrea NetworkPolicy也进行了一些增强：支持审计日志轮换配置以及Namespaced Group Membership API。在新的版本，我们也简化了Windows节点的部署流程，无需手动安装依赖项，同时多集群现在也可以通过一个统一的清单文件一键部署。
以下是本版本更新的详细清单：

## 主要功能

- 新增Egress速率限制配置，用于限制该Egress指定Pod的南北向出口流量的速率。（#5425, @GraysonWu）
- 在Egress状态中添加IPAllocated和IPAssigned字段，可以查询Egress IP的分配和挂载状态，以提高Egress的可见性。（#5282, @AJPL88 @tnqn）
- 在SupportBundle中为Antrea Agent和Antrea Controller添加goroutine stack dump。（#5538, @aniketraj1947）
- 在AntreaProxy服务的健康检查中添加“X-Load-Balancing-Endpoint-Weight”标头。（#5299, @hongliangl）
- 在Antrea Agent配置中为审计日志添加日志轮转配置。（#5337 #5366, @antoninbas @mengdie-song）
- 为Antrea Go clientset添加GroupMembers API分页支持。（#5533, @qiyueyao）
- 为Antrea Controller添加Namespaced Group Membership API。（#5380, @qiyueyao）
- 在VLAN网络上支持Pod的secondary interface。（#5341 #5365 #5279, @jianjuns）
- 支持Windows OVS容器在主机环境上直接运行，无需提前手动安装某些依赖项。（#5440, @NamanAg30）
- 更新Install-WindowsCNI-Containerd.ps1脚本，使其兼容containerd 1.7。（#5528, @NamanAg30）
- 为Multi-cluster leader集群添加新的一键安装yaml，并更新Multi-cluster用户指南。（#5389 #5531, @luolanzone）
- 在删除ClusterSet时清理leader和member集群中自动生成的资源，并在member集群重新加入ClusterSet时重新创建资源。（#5351 #5410, @luolanzone）

## 其他变更

- 多个API从Beta版本升级至GA版本，Antrea配置文件中相应的功能开关已移除。
   将EndpointSlice功能提升至GA版本。（#5393, @hongliangl）
   将NodePortLocal功能提升至GA版本。（#5491, @hjiajing）
   将AntreaProxy功能门提至GA版本，并添加antreaProxy.enable选项，以允许用户禁用该功能。（#5401, @hongliangl）
- 使antrea-controller不容忍不可达的Node，以加速故障转移过程。（#5521, @tnqn）
- 改进antctl get featuregates输出。（#5314, @cr7258）
- 提高PacketInMeter的限制速率和PacketInQueue的大小。（#5460, @GraysonWu）
- 为Flow Aggregator的Helm values添加hostAliases。（#5386, @yuntanghsu）
- 解除审计日志对AntreaPolicy功能开关的依赖，允许禁用AntreaPolicy时启用NetworkPolicy的日志记录。（#5352, @qiyueyao）
- 将Traceflow CRD验证更改为webhook验证。（#5230, @shi0rik0）
- 停止在Antrea Agent中使用/bin/sh，并直接调用二进制文件执行OVS命令。（#5364, @antoninbas）
- 仅在启用Antrea Multi-cluster时，在EndpointDNAT表中为嵌套服务安装流。（#5411, @hongliangl）
- 允许用户配置PacketIn消息的速率限制；对于依赖PacketIn消息的多个功能（例如Traceflow），都使用相同的速率限制值，但针对每个功能独立执行限制。（#5450, @GraysonWu）
- 将ARPSpoofGuardTable中默认流的动作更改为drop，有效防止ARP欺骗。（#5378, @hongliangl）
- 删除ConfigMap名称的自动后缀，并在Windows yaml的Deployment注释中添加配置校验和，以在更新Antrea时避免残留旧的ConfigMaps，同时保留Pod的自动滚动更新。（#5545, @Atish-iaf）
- 在Antrea多集群的leader集群中为ClusterSet删除行为添加webhook，防止存在任何MemberClusterAnnounce资源的情况下删除ClusterSet。（#5475, @luolanzone）
- 将Go版本更新至v1.21。（#5377, @antoninbas）


## 问题修复

- 移除MulticastGroup API对NetworkPolicyStats功能开关的依赖，以修复即使启用了Multicast的情况下，用户运行kubectl get multicastgroups时仍出现空列表的问题。（#5367, @ceclinux）
- 修复Traceflow使用IPv6地址时antctl tf命令失败的问题。（#5588, @Atish-iaf）
- 修复NetworkPolicy Controller中的死锁问题，此问题可能导致FQDN解析失败。（#5566 #5583, @Dyanngg @tnqn）
- 修复NetworkPolicy span计算问题，避免多个NetworkPolicies具有相同选择器时可能产生过期数据的问题。（#5554, @tnqn）
- 获取Node地址时仅使用第一个匹配地址，以确保找到正确的传输接口。（#5529, @xliuxu）
- 修复CNI服务在CmdAdd失败后触发回滚调用的问题，并改进日志记录。（#5548, @antoninbas）
- 在Antrea网络的MTU超过Suricata支持的最大值时输出错误日志。（#5408, @hongliangl）
- 在路由控制器中避免删除IPv6链路本地路由，以修复跨节点的Pod流量或Pod到外部流量的通信问题。（#5483, @wenyingd）
- 不再将Egress应用于访问ServiceCIDRs的流量，以避免性能问题和一些异常行为。（#5495, @tnqn）
- 统一TCP和UDP DNS拦截流规则，以修复DNS响应的无效流匹配问题。（#5392, @GraysonWu）
- 更改PacketInQueue的burst设置，以减少应用FQDN策略的Pod的DNS响应延迟。（#5456, @tnqn）
- 修复Install-OVS.ps1在Windows上SSL依赖库下载失败的问题。（#5510, @XinShuYang）
- 避免将Windows antrea-agents加入到memberlist集群，防止产生一些误导性的错误日志。（#5434, @tnqn）
- 修复antctl proxy未使用用户指定端口的问题。（#5435, @tnqn）
- 在桥接模式下，根据需要在OVS内部端口上启用IPv6，以修复启用IPAM时Agent崩溃的问题。（#5409, @antoninbas）
- 修复处理ANP命名端口时缺少协议信息的问题，以确保可以正确执行OVS中的规则。（#5370, @Dyanngg）
- 修复在Agent无法连接到K8s API时的错误日志。（#5353, @tnqn）
- 修复Antrea Multi-cluster中ClusterSet状态未更新的bug。（#5338, @luolanzone）
- 修复Antrea Multi-cluster启用enableStretchedNetworkPolicy的情况下，Antrea Controller处理LabelIdentity时Pod空标签导致的崩溃问题。（#5404 #5449, @Dyanngg）
- 始终初始化ovs_meter_packet_dropped_count指标，以修复在系统不支持OVS Meter的情况下指标未显示的问题。（#5413, @tnqn）
- 为避免RBAC警告导致日志泛滥，运行VM Agent模式跳过不需要的模块的启动。（#5391, @mengdie-song）


## 致谢

感谢参与Antrea开源社区的每一位贡献者！


[@AJPL88]: https://github.com/AJPL88
[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@XinShuYang]: https://github.com/XinShuYang
[@aniketraj1947]: https://github.com/aniketraj1947
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@cr7258]: https://github.com/cr7258
[@hongliangl]: https://github.com/hongliangl
[@hjiajing]: https://github.com/hjiajing
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@qiyueyao]: https://github.com/qiyueyao
[@shi0rik0]: https://github.com/shi0rik0
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
[@yuntanghsu]: https://github.com/yuntanghsu


## Antrea中文社区

✨ GitHub：https://github.com/antrea-io/antrea

💻 官网：https://antrea.io

👨‍💻 微信群：请搜索添加“Antrea”微信官方公众号进群





## 参考链接


[1]Antrea:

https://github.com/antrea-io/antrea

[2]v1.14.0:

https://github.com/antrea-io/antrea/releases/tag/v1.14.0


[3] Theia v0.8.0:

https://github.com/antrea-io/theia/releases/tag/v0.8.0