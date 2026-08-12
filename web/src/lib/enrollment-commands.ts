export const enrollmentTokenFile = './laneway.code'

function controllerHost(value: string) {
  const host = value.trim()
  if (!host || /\s/.test(host)) throw new Error('Controller host must not be empty or contain whitespace.')
  return host
}

export function durableNodeEnrollmentCommand(host: string) {
  return `sudo laneway node install ${controllerHost(host)} --token-file ${enrollmentTokenFile}`
}

export function userEnrollmentCommand(host: string, enrollment: 'Remembered' | 'Ephemeral') {
  const authority = controllerHost(host)
  return enrollment === 'Ephemeral'
    ? `laneway connect ${authority} --ephemeral --token-file ${enrollmentTokenFile}`
    : `laneway login ${authority} --token-file ${enrollmentTokenFile}`
}
