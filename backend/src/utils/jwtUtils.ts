import jwt from 'jsonwebtoken';

const generateTokens = (id: string, role: string) => {
  const accessToken = jwt.sign({ id, role }, process.env.JWT_SECRET as string, {
    expiresIn: '15m',
  });

  const refreshToken = jwt.sign(
    { id, role },
    process.env.REFRESH_TOKEN_SECRET as string,
    {
      expiresIn: '7d',
    }
  );

  return { accessToken, refreshToken };
};

export default generateTokens;
