# Use Node.js 18 LTS Alpine for smaller image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S authuser -u 1001

# Copy application code
COPY --chown=authuser:nodejs . .

# Create necessary directories
RUN mkdir -p /app/logs /app/exports && \
    chown -R authuser:nodejs /app/logs /app/exports

# Switch to non-root user
USER authuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js

# Start application
CMD ["node", "src/app.js"]