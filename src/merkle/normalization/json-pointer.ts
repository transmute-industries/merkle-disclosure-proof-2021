import pointer from 'json-pointer';

const objectToMessages = (obj: any) => {
  const dict = pointer.dict(obj);
  const messages = Object.keys(dict).map(key => {
    return `{"${key}": "${dict[key]}"}`;
  });
  return messages;
};

const messagesToObject = (messages: string[]) => {
  const obj = {};
  messages
    .map(m => {
      return JSON.parse(m);
    })
    .forEach(m => {
      const [key] = Object.keys(m);
      const value = m[key];
      pointer.set(obj, key, value);
    });
  return obj;
};

export { objectToMessages, messagesToObject };
