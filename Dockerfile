ARG NODE_VERSION=22.15.0
FROM node:${NODE_VERSION}-alpine
WORKDIR /app
COPY package.json .
RUN npm install
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY . .
RUN mkdir logs && chown appuser:appgroup logs
RUN npx prisma generate
RUN npm run build
EXPOSE 5555
USER appuser
CMD ["npm", "run", "start:prod"]
