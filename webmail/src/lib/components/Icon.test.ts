import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import Icon from './Icon.svelte';

describe('Icon', () => {
  it('renders Trash2 as an svg element', () => {
    const { container } = render(Icon, { name: 'Trash2' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders CalendarClock as an svg element', () => {
    const { container } = render(Icon, { name: 'CalendarClock' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders BellOff as an svg element', () => {
    const { container } = render(Icon, { name: 'BellOff' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders ArrowLeft as an svg element', () => {
    const { container } = render(Icon, { name: 'ArrowLeft' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders Paperclip as an svg element', () => {
    const { container } = render(Icon, { name: 'Paperclip' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders Mail as an svg element', () => {
    const { container } = render(Icon, { name: 'Mail' });
    expect(container.querySelector('svg')).not.toBeNull();
  });

  it('renders Plus as an svg element', () => {
    const { container } = render(Icon, { name: 'Plus' });
    expect(container.querySelector('svg')).not.toBeNull();
  });
});
