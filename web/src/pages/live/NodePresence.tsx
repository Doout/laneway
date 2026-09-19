import { useEffect, useState } from 'react'
import { useControlPlane } from '../../lib/control-plane'
import type { NodeLocation } from '../../generated/management-v1/generated/types.gen'
import { Status } from '../../components/ui'
import { time } from './shared'

export function useNodePresence(networkIds: string[]) {
  const { request } = useControlPlane()
  const [records, setRecords] = useState<Record<string, NodeLocation>>({})
  const [unavailable, setUnavailable] = useState(true)
  const key = networkIds.join(',')
  useEffect(() => {
    let active = true
    let pending = false
    const refresh = async () => {
      if (pending) return
      pending = true
      try {
        const results = await Promise.all(key.split(',').filter(Boolean).map(id => request<{ node_locations: NodeLocation[] }>(`/v1/admin/networks/${id}/node-locations?limit=1000`)))
        if (active) { setRecords(Object.fromEntries(results.flatMap(result => result.node_locations).map(value => [value.node_id, value]))); setUnavailable(false) }
      } catch { if (active) setUnavailable(true) }
      finally { pending = false }
    }
    void refresh()
    const interval = setInterval(() => { void refresh() }, 15000)
    return () => { active = false; clearInterval(interval) }
  }, [key, request])
  return { records, unavailable }
}

export function NodePresence({ record, unavailable }: { record?: NodeLocation; unavailable: boolean }) {
  const recent = record?.last_seen_unix_seconds && Date.now() / 1000 - record.last_seen_unix_seconds < 360
  const online = record?.online && recent
  return <><Status tone={unavailable ? 'muted' : online ? 'positive' : 'muted'}>{unavailable ? 'Status unavailable' : online ? 'Online' : record?.last_seen_unix_seconds || record?.identity_active === false ? 'Offline' : 'No heartbeat'}</Status>
    {record?.identity_active === false && <small>Node credentials inactive</small>}
    <small>{record?.last_seen_unix_seconds ? `Last seen ${time(record.last_seen_unix_seconds)}` : 'No authenticated report yet'}</small>
    {record?.public_ip && <small>Public IP <code>{record.public_ip}</code></small>}</>
}
