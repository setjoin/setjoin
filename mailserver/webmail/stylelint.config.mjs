/** @type {import("stylelint").Config} */
export default {
	extends: ["stylelint-config-standard", "stylelint-config-html/svelte"],
	cache: true,
	maxWarnings: 0,
	reportDescriptionlessDisables: true,
	reportInvalidScopeDisables: true,
	reportNeedlessDisables: true,
	reportUnscopedDisables: true,
	rules: {
		"custom-property-pattern": null,
		"custom-property-empty-line-before": null,
		"selector-class-pattern": null,
		"keyframes-name-pattern": null,
		"no-descending-specificity": null,
		"alpha-value-notation": "number",
		"color-function-notation": "legacy",
		"color-hex-length": "long",
		"import-notation": null,
		"declaration-block-single-line-max-declarations": null,
		"rule-empty-line-before": null,
		"comment-empty-line-before": null,
		"media-feature-range-notation": null,
	},
	overrides: [
		{
			name: "Svelte component styles",
			files: ["**/*.svelte"],
			rules: {
				"selector-pseudo-class-no-unknown": [
					true,
					{ ignorePseudoClasses: ["global"] },
				],
			},
		},
	],
};
