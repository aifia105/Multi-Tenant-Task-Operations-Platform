FROM node:20-alpine AS base

RUN npm i -g pnpm 

FROM base AS dependencies

WORKDIR /app

COPY package.json pnpm-lock.yaml ./

RUN pnpm install --frozen-lockfile

FROM base AS build

WORKDIR /app

COPY . .

COPY --from=dependencies /app/node_modules ./node_modules

RUN pnpm build

FROM base AS prod-dependencies

WORKDIR /app

COPY package.json pnpm-lock.yaml ./

RUN pnpm install --prod --frozen-lockfile

FROM base AS deploy

WORKDIR /app

ARG ENV=production
ENV NODE_ENV=$ENV

COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules

EXPOSE 3000

CMD ["node", "dist/main.js"]

