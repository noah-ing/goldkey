FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
# `pg` was added in an offline build environment. `npm install` reconciles the
# checked-in lock on the first connected build; commit the refreshed lock before
# switching this line back to `npm ci`.
RUN npm install --omit=dev --ignore-scripts && npm cache clean --force

COPY src ./src
COPY agent ./agent
COPY TERMS.md ./TERMS.md

RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 8402
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8402)+'/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "src/server.mjs"]
