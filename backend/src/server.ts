import express from 'express';
import dotenv from 'dotenv';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import globalErrorHandler from './middleware/globalErrorHandler';
import connectDB from './config/db';

dotenv.config();

connectDB();

const app = express();
const PORT = process.env.PORT;

app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

app.get('/test', (_req, res) => {
  res.send('Server with Morgan and CORS is running 🚀');
});

app.use(express.json());
app.use(cookieParser());

// app.use('/', routes);

app.use(globalErrorHandler);

app.listen(PORT, () => {
  console.log(`Server is listening on port ${PORT}`);
});
