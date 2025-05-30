import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    if (!process.env.MONGO_URL) {
      throw new Error('MONGO_URL is not defined in the environment variables');
    }

    await mongoose.connect(process.env.MONGO_URL);
    console.log('MongoDB connected');
  } catch (error) {
    console.error(`Error: ${error}`);
    process.exit(1);
  }
};

export default connectDB;
