import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import LoginPage from './+page.svelte';

describe('Login Page — Task 3 step-1 (password)', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}), text: async () => '' }));
		// Mock window.location.hostname for footer
		Object.defineProperty(window, 'location', {
			value: { hostname: 'mail.acme.com' },
			writable: true
		});
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	// ── Layout & branding ──

	it('renders wordmark <img> with setjoin alt text', () => {
		render(LoginPage);
		const img = screen.getByAltText('setjoin');
		expect(img).toBeTruthy();
		expect(img.tagName).toBe('IMG');
	});

	it('renders a card with sj-login-card class (border via setjoin token)', () => {
		render(LoginPage);
		const card = document.querySelector('.sj-login-card');
		expect(card).toBeTruthy();
		// The card uses `border: 1px solid var(--border-default)` — verify
		// the element exists with the correct class (token resolution is
		// environment-dependent).
		expect(card!.classList.contains('sj-login-card')).toBe(true);
	});

	// ── Form fields — M1 primitives ──

	it('renders Input with label "Email" and type email', () => {
		render(LoginPage);
		const emailInput = screen.getByLabelText('Email') as HTMLInputElement;
		expect(emailInput).toBeTruthy();
		expect(emailInput.type).toBe('email');
	});

	it('renders Input with label "Password" and type password', () => {
		render(LoginPage);
		const passwordInput = screen.getByLabelText('Password') as HTMLInputElement;
		expect(passwordInput).toBeTruthy();
		expect(passwordInput.type).toBe('password');
	});

	it('renders Checkbox with "Remember this device" label', () => {
		render(LoginPage);
		expect(screen.getByText(/Remember this device for 30 days/)).toBeTruthy();
	});

	// ── Submit button ──

	it('renders Button with "Continue" label', () => {
		render(LoginPage);
		expect(screen.getByRole('button', { name: /Continue/ })).toBeTruthy();
	});

	it('submit button is an M1 button with primary variant and lg size', () => {
		render(LoginPage);
		const btn = screen.getByRole('button', { name: /Continue/ });
		expect(btn.classList.contains('sj-btn--primary')).toBe(true);
		expect(btn.classList.contains('sj-btn--lg')).toBe(true);
	});

	it('submit button is disabled when email and password are empty', () => {
		render(LoginPage);
		const btn = screen.getByRole('button', { name: /Continue/ }) as HTMLButtonElement;
		expect(btn.disabled).toBe(true);
	});

	it('submit button is enabled when email and password are filled', async () => {
		render(LoginPage);
		const emailInput = screen.getByLabelText('Email');
		const passwordInput = screen.getByLabelText('Password');
		await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		const btn = screen.getByRole('button', { name: /Continue/ }) as HTMLButtonElement;
		expect(btn.disabled).toBe(false);
	});

	// ── Forgot password link ──

	it('renders "Forgot password?" link', () => {
		render(LoginPage);
		expect(screen.getByText(/Forgot password\?/)).toBeTruthy();
	});

	// ── Footer ──

	it('renders footer with hostname and self-hosted copy', () => {
		render(LoginPage);
		const hostnameEls = screen.getAllByText(/mail\.acme\.com/);
		expect(hostnameEls.length).toBeGreaterThanOrEqual(1);
		expect(screen.getByText(/self-hosted with setjoin/)).toBeTruthy();
	});

	it('renders footer data-local line', () => {
		render(LoginPage);
		expect(screen.getByText(/All data stays on your hardware/)).toBeTruthy();
	});

	// ── No Liquid Glass ──

	it('does not render any glass-pane class', () => {
		render(LoginPage);
		const glassPanes = document.querySelectorAll('.glass-pane');
		expect(glassPanes.length).toBe(0);
	});

	it('does not render any glass-modal class', () => {
		render(LoginPage);
		const glassModals = document.querySelectorAll('.glass-modal');
		expect(glassModals.length).toBe(0);
	});

	// ── i18n heading ──

	it('shows "Sign In" heading', () => {
		render(LoginPage);
		expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy();
	});

	// ── Task 4 & 5: TOTP MFA + Threat state verification ──

	describe('Login Page — Tasks 4+5 (TOTP MFA + threat states)', () => {
		it('MFARequiredError is importable from auth store', async () => {
			const { MFARequiredError } = await import('$lib/stores/auth');
			expect(MFARequiredError).toBeDefined();
			const err = new MFARequiredError('MFA needed', 'token-xyz');
			expect(err).toBeInstanceOf(Error);
			expect(err.mfaToken).toBe('token-xyz');
		});

		it('verifyTOTP is importable from auth store', async () => {
			const { verifyTOTP } = await import('$lib/stores/auth');
			expect(verifyTOTP).toBeInstanceOf(Function);
		});

		it('ThreatBlockedError is importable and has correct shape', async () => {
			const { ThreatBlockedError } = await import('$lib/stores/auth');
			const err = new ThreatBlockedError('captcha', 'What is 3+7?', 'tok', 30);
			expect(err.category).toBe('captcha');
			expect(err.captchaPrompt).toBe('What is 3+7?');
			expect(err.captchaToken).toBe('tok');
			expect(err.retryAfterSecs).toBe(30);
		});

		it('loginWithCaptcha is importable from auth store', async () => {
			const { loginWithCaptcha } = await import('$lib/stores/auth');
			expect(loginWithCaptcha).toBeInstanceOf(Function);
		});

		it('startWebAuthnLogin is importable from auth store', async () => {
			const { startWebAuthnLogin } = await import('$lib/stores/auth');
			expect(startWebAuthnLogin).toBeInstanceOf(Function);
		});

		it('TOTP i18n keys exist', async () => {
			const mod = await import('$lib/i18n/en');
			const en = mod.default as Record<string, string>;
			expect(en['mfa.totp_title']).toBe('Two-step verification');
			expect(en['mfa.totp_subtitle']).toBe('Enter the 6-digit code from your authenticator app.');
			expect(en['mfa.totp_placeholder']).toBe('000 000');
			expect(en['mfa.sign_in']).toBe('Sign in');
		});

		it('threat i18n keys exist', async () => {
			const mod = await import('$lib/i18n/en');
			const en = mod.default as Record<string, string>;
			expect(en['login.threat.captcha_title']).toBe('Security check');
			expect(en['login.threat.rate_limited']).toBe('Too many attempts. Wait a moment and try again.');
			expect(en['login.threat.blocked']).toBe('Access is blocked from this location.');
		});

		it('login page renders without errors', () => {
			// Smoke test: the component mounts and renders the login form
			const { container } = render(LoginPage);
			expect(container.querySelector('.sj-login-page')).toBeTruthy();
			expect(container.querySelector('.sj-login-card')).toBeTruthy();
		});

		// ── Task 4: TOTP MFA step-2 rendering ──

		describe('Login Page — Task 4 TOTP MFA step-2 UI', () => {
			beforeEach(() => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 202,
							ok: true,
							json: async () => ({ status: 'mfa_required', mfa_token: 'test-mfa-token' }),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));
				Object.defineProperty(window, 'location', {
					value: { hostname: 'mail.acme.com' },
					writable: true
				});
			});

			afterEach(() => {
				vi.unstubAllGlobals();
			});

			async function triggerMFAState() {
				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				const btn = screen.getByRole('button', { name: /Continue/ });
				await fireEvent.click(btn);
			}

			it('renders title "Two-step verification" after MFA is triggered', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Two-step verification/ })).toBeTruthy();
				});
			});

			it('renders subtitle with 6-digit code instructions', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByText(/Enter the 6-digit code from your authenticator app/)).toBeTruthy();
				});
			});

			it('renders mono Input with numeric inputMode and placeholder "000 000"', async () => {
				await triggerMFAState();
				await waitFor(() => {
					const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
					expect(totpInput).toBeTruthy();
					expect(totpInput.inputMode).toBe('numeric');
				});
				const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
				expect(totpInput.placeholder).toBe('000 000');
			});

			it('TOTP code input is centered (text-align: center)', async () => {
				await triggerMFAState();
				await waitFor(() => {
					const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
					expect(totpInput).toBeTruthy();
				});
				const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
				expect(totpInput.style.textAlign).toBe('center');
			});

			it('renders "Sign in" Button disabled when fewer than 6 digits', async () => {
				await triggerMFAState();
				await waitFor(() => {
					const signInBtn = screen.getByRole('button', { name: /Sign in/ }) as HTMLButtonElement;
					expect(signInBtn).toBeTruthy();
					expect(signInBtn.disabled).toBe(true);
				});
			});

			it('"Sign in" Button becomes enabled when 6 digits entered', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByRole('button', { name: /Sign in/ })).toBeTruthy();
				});
				const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
				await fireEvent.input(totpInput, { target: { value: '123456' } });
				const signInBtn = screen.getByRole('button', { name: /Sign in/ }) as HTMLButtonElement;
				expect(signInBtn.disabled).toBe(false);
			});

			it('renders "Use a passkey instead" text button', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByText(/Use a passkey instead/)).toBeTruthy();
				});
			});

			it('renders "Back to sign in" text button', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByText(/Back to sign in/)).toBeTruthy();
				});
			});

			it('does NOT render email input when in TOTP step', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Two-step verification/ })).toBeTruthy();
				});
				expect(screen.queryByLabelText('Email')).toBeNull();
			});

			it('does NOT render password input when in TOTP step', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Two-step verification/ })).toBeTruthy();
				});
				expect(screen.queryByLabelText('Password')).toBeNull();
			});

			it('does NOT render the "Continue" button (step-1) when in TOTP step', async () => {
				await triggerMFAState();
				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Two-step verification/ })).toBeTruthy();
				});
				expect(screen.queryByRole('button', { name: /Continue/ })).toBeNull();
			});

			// ── Task 4: TOTP submit actually verifies (regression: handleMFAVerify wiring) ──

			it('clicking "Sign in" in the TOTP step calls /auth/totp/verify (not a second /auth/login)', async () => {
				const calls: { url: string; method: string }[] = [];
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					const method = init?.method ?? 'GET';
					calls.push({ url: urlStr, method });
					if (urlStr.includes('/auth/login') && method === 'POST') {
						return {
							status: 202,
							ok: true,
							json: async () => ({ status: 'mfa_required', mfa_token: 'test-mfa-token' }),
							text: async () => ''
						};
					}
					if (urlStr.includes('/auth/totp/verify') && method === 'POST') {
						return { status: 200, ok: true, json: async () => ({}), text: async () => '' };
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'user@acme.com' } });
				await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Two-step verification/ })).toBeTruthy();
				});

				const totpInput = document.querySelector('.sj-input--mono') as HTMLInputElement;
				await fireEvent.input(totpInput, { target: { value: '123456' } });
				await fireEvent.click(screen.getByRole('button', { name: /Sign in/ }));

				await waitFor(() => {
					const verifyCalls = calls.filter((c) => c.url.includes('/auth/totp/verify') && c.method === 'POST');
					expect(verifyCalls.length).toBeGreaterThanOrEqual(1);
				});

				// Exactly one /auth/login POST should have happened (the first step) —
				// submitting the TOTP step must NOT re-run the password flow.
				const loginPosts = calls.filter((c) => c.url.includes('/auth/login') && c.method === 'POST');
				expect(loginPosts.length).toBe(1);
			});

			it('turns mandatory first-login MFA into an actionable authenticator enrollment step', async () => {
				const calls: string[] = [];
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
					const urlStr = String(url);
					calls.push(urlStr);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 403,
							ok: false,
							json: async () => ({ status: 'mfa_enrollment_required', mfa_token: 'enroll-token' }),
							text: async () => ''
						};
					}
					if (urlStr.includes('/auth/totp/enroll/setup') && init?.method === 'POST') {
						return {
							status: 200,
							ok: true,
							json: async () => ({ provisioning_uri: 'otpauth://totp/SetJoin:user?secret=JBSWY3DPEHPK3PXP&issuer=SetJoin' }),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'user@acme.com' } });
				await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Set up your authenticator/ })).toBeTruthy();
					expect(screen.getByLabelText('Manual setup key').textContent).toContain('JBSWY3DPEHPK3PXP');
				});
				expect(screen.getByRole('button', { name: /Enable and sign in/ })).toBeTruthy();
				expect(calls.some((url) => url.includes('/auth/totp/enroll/setup'))).toBe(true);
			});

		// ── Task 5: Login threat states ──

		describe('Login Page — Task 5 threat states', () => {
			afterEach(() => {
				vi.unstubAllGlobals();
			});

			it('shows CAPTCHA UI when server returns 403 captcha', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 403,
							ok: false,
							json: async () => ({
								error: 'captcha',
								captcha_prompt: 'What is 3 + 7?',
								captcha_token: 'tok-abc-123'
							}),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByRole('heading', { name: /Security check/ })).toBeTruthy();
				});
				expect(screen.getByText('What is 3 + 7?')).toBeTruthy();
				expect(screen.getByLabelText('Answer')).toBeTruthy();
				expect(screen.getByRole('button', { name: /Submit answer/ })).toBeTruthy();
			});

			it('shows rate-limited message when server returns 429', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 429,
							ok: false,
							json: async () => ({
								error: 'rate_limited',
								retry_after: 30
							}),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByText(/Too many attempts/)).toBeTruthy();
				});
			});

			it('shows countdown when rate-limited has retryAfterSecs', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 429,
							ok: false,
							json: async () => ({
								error: 'rate_limited',
								retry_after: 30
							}),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByText(/Try again in/)).toBeTruthy();
				});
			});

			it('shows blocked message when server returns 403 blocked', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 403,
							ok: false,
							json: async () => ({ error: 'blocked' }),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByText(/Access is blocked from this location/)).toBeTruthy();
				});
			});

			it('shows blocked message for geo_blocked category', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 403,
							ok: false,
							json: async () => ({ error: 'geo_blocked' }),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'password123' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByText(/Access is blocked from this location/)).toBeTruthy();
				});
			});

			it('shows factual error copy for invalid credentials (not "Login failed")', async () => {
				vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
					const url = typeof input === 'string' ? input :
						input instanceof URL ? input.href :
						(input as Request).url;
					const urlStr = String(url);
					if (urlStr.includes('/auth/login') && init?.method === 'POST') {
						return {
							status: 401,
							ok: false,
							json: async () => ({ detail: 'Wrong password.' }),
							text: async () => ''
						};
					}
					return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
				}));

				render(LoginPage);
				const emailInput = screen.getByLabelText('Email');
				const passwordInput = screen.getByLabelText('Password');
				await fireEvent.input(emailInput, { target: { value: 'user@acme.com' } });
				await fireEvent.input(passwordInput, { target: { value: 'wrongpass' } });
				await fireEvent.click(screen.getByRole('button', { name: /Continue/ }));

				await waitFor(() => {
					expect(screen.getByText('Wrong password.')).toBeTruthy();
				});
				expect(screen.queryByText('Login failed')).toBeNull();
			});
		});


		});
	});
});
