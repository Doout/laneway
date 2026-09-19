import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { NodePresence } from './NodePresence'
import { feature } from 'topojson-client'
import type { Topology, GeometryCollection } from 'topojson-specification'
import land from 'world-atlas/land-110m.json'
import { Button, Field, FilterSelect, SearchField } from '../../components/ui'
import { useControlPlane, type ControllerNetwork, type ControllerNode, type ControllerRoute } from '../../lib/control-plane'
import type { NodeLocation, ListNetworkNodeLocationsResponse } from '../../generated/management-v1/generated/types.gen'
import { ErrorMessage, nodeState, routeState, time } from './shared'
import './node-map.css'

export function mapPoint(latitude: number, longitude: number): [number, number] {
  return [(longitude + 180) * 2, (90 - latitude) * 2]
}

const topology = land as unknown as Topology<{ land: GeometryCollection }>
const earth = feature(topology, topology.objects.land)
const polygons = earth.features.flatMap(({ geometry }) => geometry.type === 'MultiPolygon' ? geometry.coordinates : geometry.type === 'Polygon' ? [geometry.coordinates] : [])
const landPath = polygons.map((polygon) => polygon.map((ring) => ring.map(([longitude, latitude], index) => `${index ? 'L' : 'M'}${mapPoint(latitude, longitude).join(',')}`).join(' ') + 'Z').join(' ')).join(' ')

type MapNode = { node: ControllerNode; location?: NodeLocation }
type Snapshot = { nodes: MapNode[]; routes: ControllerRoute[]; errors: string[]; automatic: boolean; limited: boolean; provider?: string }

export function groupMapNodes(nodes: MapNode[]) {
  const groups = new Map<string, { x: number; y: number; nodes: MapNode[] }>()
  for (const node of nodes) {
    const location = node.location?.location
    if (!location) continue
    const [x, y] = mapPoint(location.latitude, location.longitude)
    const key = `${Math.round(x / 12)},${Math.round(y / 12)}`
    const group = groups.get(key)
    if (group) group.nodes.push(node)
    else groups.set(key, { x, y, nodes: [node] })
  }
  return [...groups.values()]
}

export function NodeMap({ networks }: { networks: ControllerNetwork[] }) {
  const { request, hasPermission } = useControlPlane()
  const [networkFilter, setNetworkFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [snapshot, setSnapshot] = useState<Snapshot>({ nodes: [], routes: [], errors: [], automatic: false, limited: false })
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    let current = true
    setLoading(true)
    const scopes = networks.filter((network) => hasPermission('node.read', network.network_id))
    void Promise.all(scopes.map(async (network) => {
      const prefix = `/v1/admin/networks/${network.network_id}`
      try {
        const [nodes, locations, routes] = await Promise.all([
          request<{ nodes: ControllerNode[] }>(`${prefix}/nodes?limit=1000`),
          request<ListNetworkNodeLocationsResponse>(`${prefix}/node-locations?limit=1000`),
          hasPermission('route.read', network.network_id) ? request<{ routes: ControllerRoute[] }>(`${prefix}/routes?limit=1000`) : Promise.resolve({ routes: [] }),
        ])
        if (nodes.nodes.some((node) => node.network_id !== network.network_id)) throw new Error('Invalid network scope')
        const byId = new Map(locations.node_locations.map((location) => [location.node_id, location]))
        return { nodes: nodes.nodes.filter((node) => !nodeState(node).inactive).map((node) => ({ node, location: byId.get(node.node_id) })), routes: routes.routes, automatic: locations.automatic_enabled, provider: locations.location_provider, limited: nodes.nodes.length === 1000, errors: [] }
      } catch {
        return { nodes: [], routes: [], automatic: false, limited: false, errors: [`Could not load ${network.name}.`] }
      }
    })).then((results) => {
      if (!current) return
      setSnapshot({ nodes: results.flatMap((result) => result.nodes), routes: results.flatMap((result) => result.routes), errors: results.flatMap((result) => result.errors), automatic: results.some((result) => result.automatic), provider: results.find((result) => result.provider)?.provider, limited: results.some((result) => result.limited) })
      setLoading(false)
    })
    return () => { current = false }
  }, [networks, hasPermission, request, revision])

  const visible = snapshot.nodes.filter(({ node }) => (networkFilter === 'all' || node.network_id === networkFilter) && `${node.name} ${node.ipv4_address ?? ''}`.toLowerCase().includes(query.toLowerCase()))
  const groups = useMemo(() => groupMapNodes(visible), [visible])
  const selected = visible.find(({ node }) => node.node_id === selectedId)
  const located = visible.filter((value) => value.location?.location).length
  const selectedRoutes = snapshot.routes.filter((route) => route.node_id === selectedId && route.state === 'approved' && routeState(route).actionable)

  return <section className="node-map" aria-label="Node locations">
    <div className="node-map__toolbar">
      <SearchField label="Find a node on the map" placeholder="Find a node" value={query} onChange={setQuery} />
      <FilterSelect label="Map network" value={networkFilter} onChange={setNetworkFilter}><option value="all">All networks</option>{networks.filter((network) => hasPermission('node.read', network.network_id)).map((network) => <option key={network.network_id} value={network.network_id}>{network.name}</option>)}</FilterSelect>
      <Button disabled={loading} onClick={() => setRevision((value) => value + 1)}>Refresh</Button>
    </div>
    {snapshot.errors.length > 0 && <ErrorMessage value={snapshot.errors.join(' ')} />}
    <div className="node-map__layout" aria-busy={loading}>
      <div className="node-map__canvas">
        <svg viewBox="0 0 720 360" role="group" aria-label="World map of approximate node locations">
          <path d={landPath} className="node-map__land" aria-hidden="true" />
          {[-60, -30, 0, 30, 60].map((lat) => <path key={lat} d={`M0,${mapPoint(lat, 0)[1]}H720`} className="node-map__grid" aria-hidden="true" />)}
          {groups.map((group, index) => <g key={index} role="button" tabIndex={0} aria-label={`${group.nodes.length} ${group.nodes.length === 1 ? 'node' : 'nodes'} near ${group.nodes[0].location?.location?.label}`} className={`node-map__pin${group.nodes.some(({ node }) => node.node_id === selectedId) ? ' is-selected' : ''}`} onClick={() => setSelectedId(group.nodes[0].node.node_id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedId(group.nodes[0].node.node_id) } }}>
            <circle cx={group.x} cy={group.y} r={11} />
            <text x={group.x} y={group.y + 3.5} textAnchor="middle">{group.nodes.length}</text>
            <title>{group.nodes.map(({ node }) => node.name).join(', ')}</title>
          </g>)}
        </svg>
        <div className="node-map__caption"><span>{loading ? 'Loading locations…' : `${located} located · ${visible.length - located} unknown`}</span><span>Approximate public-IP locations · Map: Natural Earth{snapshot.provider === 'db-ip' && <> · <a href="https://db-ip.com" target="_blank" rel="noreferrer">IP geolocation by DB-IP</a></>}</span></div>
        {!snapshot.automatic && !loading && <p className="node-map__note">Automatic lookup is off. Configure a local City database or set locations manually.</p>}
        {snapshot.limited && <p className="node-map__note">Showing the first 1,000 nodes per network.</p>}
      </div>
      <div className="node-map__list" aria-label="Map nodes">
        {!visible.length && !loading ? <p>No current nodes match.</p> : visible.map(({ node, location }) => <button key={node.node_id} type="button" aria-pressed={selectedId === node.node_id} onClick={() => setSelectedId(node.node_id)}>
          <strong>{node.name}</strong><span>{location?.location?.label ?? 'Location unknown'}{location?.source === 'manual' ? ' · Manual' : location?.stale ? ' · Stale' : ''}</span>
          <small>{networks.find((network) => network.network_id === node.network_id)?.name}</small>
        </button>)}
      </div>
    </div>
    {selected ? <div className="node-map__detail">
      <div><h2>{selected.node.name}</h2><NodePresence record={selected.location} unavailable={false} /><p>{selected.location?.source === 'manual' ? 'Manual location' : selected.location?.location ? `Approximate IP location${selected.location.location.accuracy_km ? ` · ±${selected.location.location.accuracy_km} km` : ''}` : 'No location available'}</p>{selected.location?.observed_at_unix_seconds ? <p>Updated {time(selected.location.observed_at_unix_seconds)}{selected.location.stale ? ' · Stale' : ''}</p> : null}
        <h3>Configured routes</h3>{!hasPermission('route.read', selected.node.network_id) ? <p>Route access required.</p> : selectedRoutes.length ? <ul>{selectedRoutes.map((route) => <li key={route.route_id}>{route.kind === 'exit' ? 'Network exit' : route.prefix}</li>)}</ul> : <p>No approved routes.</p>}
        <p>Configured routes do not confirm a live connection.</p>
      </div>
      {hasPermission('node.manage', selected.node.network_id) && <LocationEditor key={`${selected.node.node_id}:${selected.location?.source}:${JSON.stringify(selected.location?.location)}`} value={selected} onSaved={() => setRevision((value) => value + 1)} />}
    </div> : <p className="node-map__note">Select a node to view its location and routes. Unknown locations stay in the list.</p>}
  </section>
}

function LocationEditor({ value, onSaved }: { value: MapNode; onSaved: () => void }) {
  const { request } = useControlPlane()
  const [label, setLabel] = useState(value.location?.location?.label ?? '')
  const [latitude, setLatitude] = useState(value.location?.location?.latitude.toString() ?? '')
  const [longitude, setLongitude] = useState(value.location?.location?.longitude.toString() ?? '')
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  async function save(event?: FormEvent) {
    event?.preventDefault()
    setPending(true); setError('')
    try {
      await request(`/v1/admin/nodes/${value.node.node_id}/location`, event ? { method: 'PUT', body: { label: label.trim(), latitude: Number(latitude), longitude: Number(longitude) } } : { method: 'DELETE' })
      onSaved()
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not save location.') }
    finally { setPending(false) }
  }
  return <form onSubmit={save} className="node-map__editor"><h3>Set location</h3>
    <Field label="Site name"><input required maxLength={253} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Toronto office" /></Field>
    <div className="node-map__coordinates"><Field label="Latitude"><input required type="number" step="any" min={-90} max={90} value={latitude} onChange={(event) => setLatitude(event.target.value)} /></Field><Field label="Longitude"><input required type="number" step="any" min={-180} max={180} value={longitude} onChange={(event) => setLongitude(event.target.value)} /></Field></div>
    <ErrorMessage value={error} /><div className="button-row"><Button type="submit" variant="primary" disabled={pending}>Save location</Button>{value.location?.source === 'manual' && <Button type="button" disabled={pending} onClick={() => void save()}>Use automatic</Button>}</div>
  </form>
}
