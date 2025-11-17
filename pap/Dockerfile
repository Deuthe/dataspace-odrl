FROM node:20-alpine
WORKDIR /app
RUN npm install express axios
COPY server.js .
EXPOSE 3000
CMD ["node", "server.js"]
