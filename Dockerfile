FROM node:18-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY app.js ./
COPY keys ./keys
COPY public ./public

# Le flag est injecte par variable d'environnement (Railway : railway variables).
ENV NODE_ENV=production

RUN addgroup -S bv && adduser -S bv -G bv && chown -R bv:bv /app
USER bv

CMD ["node", "app.js"]
