# 浮世 · Ukiyo —— 面向自主 LLM agent 的叙事一致性蜜罐
#
# 零第三方依赖：全部模块只用 CPython 标准库，镜像里没有 pip install 步骤，
# 也没有构建缓存可言 —— 构建即"复制代码 + 建用户"，几秒钟完成。
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ukiyo" \
      org.opencontainers.image.description="Narrative-consistency honeypot for autonomous LLM agents" \
      org.opencontainers.image.version="1.1.0" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HONEY_BIND=0.0.0.0 \
    HONEY_PORT=18080 \
    HONEY_SSH_PORT=20302

WORKDIR /app

# 只带运行所需模块。探针/评估脚本（llm_probe*、recount*、_selftest*、_dbg*）
# 一律不进镜像：它们含出站客户端代码，留着只会让「蜜罐不出站」这件事变成口头承诺。
COPY honey_world.py honey_world_ad.py honey_state.py honey_detect.py \
     honey_canary.py honey_evidence.py honey_narrator.py honey_server.py \
     honey_demo.py audit.py verify-docker.py ./

# 非 root 运行；runs/ 是唯一需要写入的路径（compose 会给它挂宿主目录）
RUN useradd --system --uid 10001 --create-home honey \
 && mkdir -p /app/runs \
 && chown -R honey:honey /app

USER honey

# 18080 = 诱捕 HTTP 面；20302 = 假 SSH banner 面
EXPOSE 18080 20302

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import os,urllib.request,sys; u='http://127.0.0.1:%s/'%os.environ.get('HONEY_PORT','18080'); sys.exit(0 if urllib.request.urlopen(u,timeout=2).status==200 else 1)"

ENTRYPOINT ["python3", "honey_demo.py"]
CMD ["serve", "--port", "18080", "--ssh-port", "20302"]
