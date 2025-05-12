function generatePassword(): string {
  const password = Math.floor(1000000 + Math.random() * 9000000).toString();
  return password;
}

export { generatePassword };
