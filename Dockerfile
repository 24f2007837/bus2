FROM node:22-alpine
WORKDIR /app
COPY server.js package.json ./
ENV DATA_DIR=/data
CMD ["node","server.js"]
