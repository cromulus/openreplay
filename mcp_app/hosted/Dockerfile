FROM node:22-bookworm-slim AS build
ENV COREPACK_ENABLE_AUTO_PIN=0
RUN corepack enable
WORKDIR /app
COPY player/package.json player/yarn.lock ./player/
RUN cd player && yarn install --frozen-lockfile
COPY mcp_app/package.json mcp_app/yarn.lock ./mcp_app/
RUN cd mcp_app && yarn install --frozen-lockfile
COPY player ./player
COPY mcp_app ./mcp_app
RUN cd mcp_app && yarn build && node --test hosted/gateway.test.mjs

FROM node:22-bookworm-slim
ENV NODE_ENV=production PORT=3100 MCP_DATA_DIR=/var/lib/openreplay-mcp
WORKDIR /app/mcp_app
COPY --from=build /app/mcp_app/node_modules ./node_modules
COPY --from=build /app/mcp_app/package.json ./package.json
COPY --from=build /app/mcp_app/dist ./dist
COPY --from=build /app/mcp_app/dist-server ./dist-server
COPY --from=build /app/mcp_app/hosted/gateway.mjs ./hosted/gateway.mjs
RUN mkdir -p /var/lib/openreplay-mcp && chown node:node /var/lib/openreplay-mcp
USER node
EXPOSE 3100
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:3100/mcp-health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","hosted/gateway.mjs"]
