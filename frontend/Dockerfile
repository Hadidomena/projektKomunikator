# Use a Node image for development
FROM node:20-alpine

WORKDIR /app

# Install pnpm (v9 is the last major compatible with Node 20)
RUN npm install -g pnpm@9

# Copy package definition and install dependencies
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install

# Copy configuration files and source code
COPY astro.config.mjs* ./
COPY tsconfig.json* ./
COPY src ./src
COPY public* ./public

# The command to start the dev server will be in docker-compose.yml
# Expose the Astro dev server port
EXPOSE 4321

CMD ["pnpm", "run", "dev", "--", "--host", "0.0.0.0"]
