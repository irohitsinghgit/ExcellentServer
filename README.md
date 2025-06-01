# Excellent Institute API

A modern, optimized Node.js application with best practices and security features.

## Features

- 🚀 Express.js framework
- 🔒 Security middleware (Helmet, CORS, Rate Limiting)
- 📝 Winston logging
- 🔄 Nodemon for development
- 🧪 Jest testing setup
- 📦 Compression for better performance
- ⚡ Environment configuration
- 🛡️ Error handling
- 🔄 Graceful shutdown

## Prerequisites

- Node.js >= 14.0.0
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ecellentinstitute
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:
```env
NODE_ENV=development
PORT=3000
LOG_LEVEL=info
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

## Usage

### Development
```bash
npm run dev
```
This will start the server with nodemon for automatic reloading.

### Production
```bash
npm start
```

### Testing
```bash
npm test
```

### Linting
```bash
npm run lint
```

## Project Structure

```
ecellentinstitute/
├── src/
│   └── index.js          # Main application file
├── .env                  # Environment variables
├── package.json          # Project dependencies and scripts
├── README.md            # Project documentation
└── logs/                # Log files (created at runtime)
    ├── error.log
    └── combined.log
```

## Security Features

- Helmet for security headers
- CORS protection
- Rate limiting
- Request validation
- Error handling
- Secure environment variables

## Logging

The application uses Winston for logging with the following features:
- Console logging with colors
- File logging for errors and combined logs
- Timestamp for each log entry
- Different log levels (error, info, etc.)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

ISC 