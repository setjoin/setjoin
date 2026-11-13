/**
 * COV-2 — render coverage for the identity section route wrappers.
 *
 * Every +page.svelte under `(identity)/identity/` other than the console root
 * is a thin adapter that mounts IdentityModelConsole with a fixed
 * `initialSection` (plus an optional selection/setup prop on detail and
 * "new source" routes). The console itself is exercised by `identity.test.ts`;
 * here it is stubbed so each wrapper's own statements run while we pin the
 * props the route forwards (regression net for accidental prop renames).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';

const consoleStub = vi.hoisted(() => ({
	props: [] as Array<Record<string, unknown>>
}));

vi.mock('$lib/components/admin/identity/IdentityModelConsole.svelte', () => ({
	// Svelte 5 invokes components as Component(anchorNode, props).
	default: (_anchor: unknown, props: Record<string, unknown>) => {
		consoleStub.props.push(props);
		return null;
	}
}));

import { page } from '$app/state';
import AuditPage from './audit/+page.svelte';
import ConflictsPage from './conflicts/+page.svelte';
import ConflictDetailPage from './conflicts/[id]/+page.svelte';
import PeoplePage from './people/+page.svelte';
import PersonDetailPage from './people/[id]/+page.svelte';
import SourcesPage from './sources/+page.svelte';
import SourceDetailPage from './sources/[sourceKey]/+page.svelte';
import NewSourcePage from './sources/new/+page.svelte';
import TransitionsPage from './transitions/+page.svelte';
import TransitionDetailPage from './transitions/[id]/+page.svelte';

function setParams(params: Record<string, string>) {
	(page as { params: Record<string, string> }).params = params;
}

describe('identity section wrapper pages', () => {
	beforeEach(() => {
		consoleStub.props.length = 0;
		setParams({});
	});

	it('audit mounts the console with initialSection "audit"', () => {
		render(AuditPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'audit' });
	});

	it('conflicts mounts the console with initialSection "conflicts"', () => {
		render(ConflictsPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'conflicts' });
	});

	it('conflicts/[id] forwards the route id as selectedId', () => {
		setParams({ id: '42' });
		render(ConflictDetailPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'conflicts', selectedId: '42' });
	});

	it('people mounts the console with initialSection "people"', () => {
		render(PeoplePage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'people' });
	});

	it('people/[id] forwards the route id as selectedId', () => {
		setParams({ id: 'u-7' });
		render(PersonDetailPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'people', selectedId: 'u-7' });
	});

	it('sources mounts the console with initialSection "sources"', () => {
		render(SourcesPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'sources' });
	});

	it('sources/[sourceKey] forwards the route key as selectedId', () => {
		setParams({ sourceKey: 'okta' });
		render(SourceDetailPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'sources', selectedId: 'okta' });
	});

	it('sources/new mounts the console in source-setup mode', () => {
		render(NewSourcePage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'sources', sourceSetup: true });
	});

	it('transitions mounts the console with initialSection "transitions"', () => {
		render(TransitionsPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'transitions' });
	});

	it('transitions/[id] forwards the route id as selectedId', () => {
		setParams({ id: 't-3' });
		render(TransitionDetailPage);
		expect(consoleStub.props).toHaveLength(1);
		expect(consoleStub.props[0]).toMatchObject({ initialSection: 'transitions', selectedId: 't-3' });
	});
});
