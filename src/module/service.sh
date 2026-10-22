#!/system/bin/sh
#######################################
# 文件: service.sh
# 功能: Magisk/KernelSU/APatch service 阶段启动桥接。
# 用法: 由模块框架无参数调用。
# 依赖: su、netproxyctl
#######################################

readonly MODDIR="$(cd "$(dirname "$0")" && pwd)"
readonly NETPROXY_BIN="$MODDIR/bin/netproxyctl"

[ "$#" -eq 0 ] || {
  printf '%s\n' 'service.sh 仅供模块 service 阶段调用；请使用 netproxyctl service 管理服务。' >&2
  exit 2
}

[ -x "$NETPROXY_BIN" ] || exit 1

# 配套包的开机依赖等待，不承担服务管理或配置生成。
# AGH 先加载大规则库；避免 NetProxy 自启动过早将 DNS 送往尚未监听的端口。
if [ -d "$MODDIR/compat/agh" ]; then
  resetprop -w sys.boot_completed 0 || exit 1
  agh_waited=0
  while ! awk 'NR > 1 && $2 == "0100007F:15D7" { ready=1 } END { exit !ready }' /proc/net/udp; do
    if [ "$agh_waited" -ge 150 ]; then
      printf '%s\n' 'AGH:5591 尚未就绪，请检查 ADG；NetProxy 保留诊断入口，不改用其他 DNS。' >&2
      break
    fi
    sleep 1
    agh_waited=$((agh_waited + 1))
  done
fi

# 通过 su 启动原生进程；sing-box 的最终 cgroup 归属由 Go 在启动时显式收敛。
if command -v su > /dev/null 2>&1; then
  exec su -c "\"$NETPROXY_BIN\" __internal boot --module-dir \"$MODDIR\""
fi
exec "$NETPROXY_BIN" __internal boot --module-dir "$MODDIR"
