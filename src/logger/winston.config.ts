import * as winston from 'winston'
import 'winston-daily-rotate-file'
import * as winstonMongoDB from 'winston-mongodb'

const mongoUrl = process.env.MONGODB_URL
const mongoDbName = process.env.MONGODB_NAME

const transports = [
  // transport: console
  new winston.transports.Console({
    format: winston.format.combine(
      // Add a timestamp to the console logs
      winston.format.timestamp(),
      // Add colors to you logs
      winston.format.colorize(),
      // What the details you need as logs
      winston.format.printf(({ timestamp, level, message, context, trace }) => {
        const stackTrace = trace ? `\n${trace}` : ''
        return `${timestamp} [${context}] ${level}: ${message}${stackTrace}`
      }),
    ),
  }),

  // transport: fichier journalier
  new winston.transports.DailyRotateFile({
    filename: 'logs/application-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '14d',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json(),
    ),
  }),

  // transport: mongodb / level info
  new winstonMongoDB.MongoDB({
    level: 'info',
    db: mongoUrl,
    dbName: mongoDbName,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    },
    collection: 'logs',
    format: winston.format.combine(
      winston.format.timestamp(), // timestamp 
      winston.format.json(), // formatJSON
    ),
  }),

];

// on exporte le logger:
export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports,
  exitOnError: false,
});