// mailserver/webmail/src/lib/components/ui/Menu.test.ts
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import Menu from './Menu.svelte';

const items = [
	{ id: 'open', label: 'Open' },
	{ id: 'rename', label: 'Rename' },
	{ id: 'delete', label: 'Delete', destructive: true }
];

async function openViaClick() {
	const trigger = screen.getByRole('button', { name: 'Actions' });
	await fireEvent.click(trigger);
	await tick();
	return trigger;
}

describe('Menu', () => {
	it('renders a closed trigger with menu button semantics', () => {
		render(Menu, { items, label: 'Actions' });
		const trigger = screen.getByRole('button', { name: 'Actions' });
		expect(trigger).toHaveAttribute('aria-haspopup', 'menu');
		expect(trigger).toHaveAttribute('aria-expanded', 'false');
		expect(screen.queryByRole('menu')).toBeNull();
	});

	it('opens on click and focuses the first item', async () => {
		render(Menu, { items, label: 'Actions' });
		const trigger = await openViaClick();
		expect(trigger).toHaveAttribute('aria-expanded', 'true');
		expect(screen.getByRole('menu')).toBeInTheDocument();
		const menuitems = screen.getAllByRole('menuitem');
		expect(menuitems).toHaveLength(3);
		expect(menuitems[0]).toHaveFocus();
	});

	it('moves focus with ArrowDown/ArrowUp and wraps at both ends', async () => {
		render(Menu, { items, label: 'Actions' });
		await openViaClick();
		const menuitems = screen.getAllByRole('menuitem');
		await fireEvent.keyDown(menuitems[0], { key: 'ArrowDown' });
		expect(menuitems[1]).toHaveFocus();
		await fireEvent.keyDown(menuitems[1], { key: 'ArrowDown' });
		expect(menuitems[2]).toHaveFocus();
		await fireEvent.keyDown(menuitems[2], { key: 'ArrowDown' });
		expect(menuitems[0]).toHaveFocus(); // wraps forward
		await fireEvent.keyDown(menuitems[0], { key: 'ArrowUp' });
		expect(menuitems[2]).toHaveFocus(); // wraps backward
	});

	it('jumps with Home and End', async () => {
		render(Menu, { items, label: 'Actions' });
		await openViaClick();
		const menuitems = screen.getAllByRole('menuitem');
		await fireEvent.keyDown(menuitems[0], { key: 'End' });
		expect(menuitems[2]).toHaveFocus();
		await fireEvent.keyDown(menuitems[2], { key: 'Home' });
		expect(menuitems[0]).toHaveFocus();
	});

	it('closes on Escape and returns focus to the trigger', async () => {
		render(Menu, { items, label: 'Actions' });
		const trigger = await openViaClick();
		await fireEvent.keyDown(screen.getAllByRole('menuitem')[0], { key: 'Escape' });
		expect(screen.queryByRole('menu')).toBeNull();
		expect(trigger).toHaveAttribute('aria-expanded', 'false');
		expect(trigger).toHaveFocus();
	});

	it('selects an item on click, closes, and refocuses the trigger', async () => {
		const onSelect = vi.fn();
		render(Menu, { items, label: 'Actions', onSelect });
		const trigger = await openViaClick();
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Rename' }));
		expect(onSelect).toHaveBeenCalledTimes(1);
		expect(onSelect).toHaveBeenCalledWith('rename');
		expect(screen.queryByRole('menu')).toBeNull();
		expect(trigger).toHaveFocus();
	});

	it('closes on pointerdown outside the menu', async () => {
		render(Menu, { items, label: 'Actions' });
		await openViaClick();
		await fireEvent.pointerDown(document.body);
		expect(screen.queryByRole('menu')).toBeNull();
	});

	it('opens from the trigger with ArrowDown (first item) and ArrowUp (last item)', async () => {
		render(Menu, { items, label: 'Actions' });
		const trigger = screen.getByRole('button', { name: 'Actions' });
		await fireEvent.keyDown(trigger, { key: 'ArrowDown' });
		await tick();
		expect(screen.getAllByRole('menuitem')[0]).toHaveFocus();
		await fireEvent.keyDown(screen.getAllByRole('menuitem')[0], { key: 'Escape' });
		await fireEvent.keyDown(trigger, { key: 'ArrowUp' });
		await tick();
		expect(screen.getAllByRole('menuitem')[2]).toHaveFocus();
	});

	it('styles destructive items with the destructive class', async () => {
		render(Menu, { items, label: 'Actions' });
		await openViaClick();
		expect(screen.getByRole('menuitem', { name: 'Delete' }).className).toContain(
			'menu__item--destructive'
		);
		expect(screen.getByRole('menuitem', { name: 'Rename' }).className).not.toContain(
			'menu__item--destructive'
		);
	});
});
