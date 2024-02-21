FROM node:20-alpine

COPY . /app

WORKDIR /app

RUN npm install

EXPOSE 8080

ENTRYPOINT ["node", "server.js"]