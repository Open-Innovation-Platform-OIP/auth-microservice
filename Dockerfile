FROM node:alpine

RUN apk --no-cache add python \
    g++ gcc libgcc libstdc++ linux-headers make python curl

RUN mkdir -p /opt/app

RUN chown node:node /opt/app

WORKDIR /opt/app

COPY --chown=node:node package.json .

USER node

RUN npm install

COPY --chown=node:node . .

EXPOSE 8080

CMD npm start