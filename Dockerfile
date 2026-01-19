# 1. Use a modern, stable Node version
FROM node:20-bookworm-slim

# 2. Standardize apt-get (removed the broken Buster snapshots)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    apt-transport-https \
    curl \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Note: liblog4j2-java=2.11.1 is highly specific to the "Juice Shop" 
# challenge. If it fails on Bookworm, it's better to use the version 
# provided by the current OS or skip it if you aren't testing Log4Shell.
RUN apt-get update && apt-get install -y --no-install-recommends \
    liblog4j2-java || echo "Warning: Specific log4j version not found, skipping..."

# Metadata Labels
ARG BUILD_DATE
ARG VCS_REF
LABEL maintainer="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.title="OWASP Juice Shop" \
    org.opencontainers.image.description="Probably the most modern and sophisticated insecure web application" \
    org.opencontainers.image.version="12.3.0" \
    org.opencontainers.image.source="https://github.com/clintonherget/juice-shop"

# 3. Setup User and Permissions
RUN addgroup --system --gid 1001 juicer && \
    adduser juicer --system --uid 1001 --ingroup juicer

WORKDIR /juice-shop
# Copying only package files first is a "Docker Best Practice" to speed up builds
COPY --chown=juicer:juicer package*.json ./
COPY --chown=juicer:juicer . .

# 4. Install dependencies
# We use --legacy-peer-deps because Juice Shop 12.x has old dependency trees
RUN sudo npm install --production --unsafe-perm --legacy-peer-deps
RUN sudo npm dedupe
RUN rm -rf frontend/node_modules

# 5. Final Folder Permissions
RUN mkdir -p logs && \
    chown -R juicer:juicer logs ftp/ frontend/dist/ data/ i18n/ && \
    chmod -R 755 logs ftp/ frontend/dist/ data/ i18n/

USER 1001
EXPOSE 3000
CMD ["npm", "start"]
