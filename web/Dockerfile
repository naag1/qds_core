FROM node:22-alpine AS build
WORKDIR /web
COPY package.json index.html ./
COPY src.jsx style.css ./
RUN npm install && npm run build
FROM nginx:1.27-alpine
COPY --from=build /web/dist /usr/share/nginx/html
