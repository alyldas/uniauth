FROM node:22-alpine AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM deps AS source

COPY . .

FROM source AS check

RUN npm run check

CMD ["npm", "run", "check"]
