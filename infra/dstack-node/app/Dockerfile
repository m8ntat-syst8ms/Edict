# Edict attested inference proxy.
#
# For a dstack deployment the compose file must reference this image BY
# DIGEST (…@sha256:…) so the CVM's measured compose_hash pins the exact
# code: build, push, then substitute the digest into docker-compose.yml.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json tsconfig.json ./
# Standalone build: tsconfig extends the monorepo base, which is not present
# in the Docker context — write a self-contained one.
RUN node -e "const fs=require('fs');const t=JSON.parse(fs.readFileSync('tsconfig.json','utf8'));delete t.extends;t.compilerOptions={target:'ES2022',module:'NodeNext',moduleResolution:'NodeNext',strict:true,declaration:true,sourceMap:true,skipLibCheck:true,forceConsistentCasingInFileNames:true,isolatedModules:true,...t.compilerOptions};fs.writeFileSync('tsconfig.json',JSON.stringify(t,null,2));"
RUN npm install --no-audit --no-fund && npm install --no-save --no-audit --no-fund @types/node@^26 typescript@^7
COPY src ./src
RUN npx tsc -p tsconfig.json && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
# /data holds the persistent signature store (mounted volume).
RUN mkdir -p /data
VOLUME /data
EXPOSE 8100
CMD ["node", "dist/main.js"]
