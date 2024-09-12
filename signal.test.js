// Just exports an AbortSignal to be used across tests
import { setMaxListeners } from 'node:events';
const signal = AbortSignal.timeout(60_000);

// Set max listeners to avoid complaints about possible memory leaks
setMaxListeners(20, signal);

export { signal };
