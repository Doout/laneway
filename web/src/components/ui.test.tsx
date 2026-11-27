import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import { Button, Field } from './ui'

it('keeps native field labeling, descriptions and form submission through the SDK', async () => {
  const user = userEvent.setup()
  const submit = vi.fn()
  render(
    <form onSubmit={event => {
      event.preventDefault()
      submit(new FormData(event.currentTarget).get('network'))
    }}>
      <span id="network-context">Connection settings.</span>
      <Field label="Network" hint="Select a network." error="Check this value.">
        <select id="network" name="network" aria-describedby="network-context">
          <option value="east">East</option>
          <option value="west">West</option>
        </select>
      </Field>
      <Button type="submit">Save</Button>
    </form>,
  )

  const control = screen.getByRole('combobox', { name: 'Network' })
  expect(screen.getByText('Network')).toHaveAttribute('for', 'network')
  expect(control).toHaveAttribute('aria-invalid', 'true')
  expect(control).toHaveAccessibleDescription('Connection settings. Select a network. Check this value.')
  expect(screen.getByRole('alert')).toHaveTextContent('Check this value.')
  await user.selectOptions(control, 'west')
  await user.click(screen.getByRole('button', { name: 'Save' }))
  expect(submit).toHaveBeenCalledWith('west')
})
