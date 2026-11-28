<svelte:options runes={true} />

<script lang="ts">
  import Icon from './Icon.svelte';
  import { t } from '$lib/i18n';

  interface Props {
    isNameSpoof?: boolean;
    senderDisplayName?: string;
    isFirstTime?: boolean;
    fromAddr?: string;
  }

  let {
    isNameSpoof = false,
    senderDisplayName = '',
    isFirstTime = false,
    fromAddr = '',
  }: Props = $props();

  let variant: 'first-time' | 'name-spoof' | 'external' = $derived(
    isNameSpoof ? 'name-spoof' : isFirstTime ? 'first-time' : 'external'
  );
</script>

<div
  class="external-sender-banner"
  class:variant-spoof={variant === 'name-spoof'}
  class:variant-first-time={variant === 'first-time'}
  class:variant-external={variant === 'external'}
  role={variant === 'name-spoof' ? 'alert' : 'note'}
  aria-label={variant === 'name-spoof'
    ? t('mail.banner.spoof_pill')
    : variant === 'first-time'
      ? t('mail.banner.first_time', { addr: fromAddr || 'unknown address' })
      : t('mail.banner.external')}
>
  <div class="banner-icon">
    {#if variant === 'name-spoof'}
      <Icon name="ShieldAlert" size={16} />
    {:else if variant === 'first-time'}
      <Icon name="Info" size={16} />
    {:else}
      <Icon name="AlertTriangle" size={16} />
    {/if}
  </div>
  <div class="banner-text">
    {#if variant === 'name-spoof'}
      <span class="spoof-warning">
        {t('mail.banner.spoof_warning')}
      </span>
      {#if senderDisplayName}
        <span class="spoof-detail">
          {t('mail.banner.spoof_detail', { name: senderDisplayName })}
        </span>
      {/if}
      <span class="spoof-pill">{t('mail.banner.spoof_pill')}</span>
    {:else if variant === 'first-time'}
      <span class="first-time-text">
        {t('mail.banner.first_time', { addr: fromAddr || 'unknown address' })}
      </span>
    {:else}
      <span class="external-text">
        {t('mail.banner.external')}
      </span>
    {/if}
  </div>
</div>

<style>
  .external-sender-banner {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    margin: 8px 0;
    border-left: 4px solid var(--banner-border);
    background: var(--banner-bg);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    font-size: var(--text-sm);
    line-height: 1.4;
  }

  /* Variant token wiring */
  .variant-spoof {
    --banner-border: var(--danger-solid);
    --banner-bg: var(--danger-bg);

    color: var(--danger-fg);
  }

  .variant-first-time {
    --banner-border: var(--success-solid);
    --banner-bg: var(--success-bg);

    color: var(--success-fg);
  }

  .variant-external {
    --banner-border: var(--warning-solid);
    --banner-bg: var(--warning-bg);

    color: var(--warning-fg);
  }

  .banner-icon {
    flex-shrink: 0;
    padding-top: 1px;
    /* Inherit the variant color so the icon matches the banner tone */
    color: inherit;
  }

  .banner-text {
    display: flex;
    flex-direction: column;
    gap: 4px;
    color: var(--text-secondary);
  }

  .external-text {
    color: var(--text-secondary);
  }

  .first-time-text {
    color: var(--text-secondary);
  }

  .spoof-warning {
    color: var(--text-primary);
    font-weight: 500;
  }

  .spoof-detail {
    font-size: var(--text-xs);
    color: var(--text-tertiary);
  }

  .spoof-pill {
    display: inline-flex;
    align-self: flex-start;
    padding: 2px 8px;
    border-radius: var(--radius-sm);
    background: var(--danger-bg);
    color: var(--danger-fg);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.04em;
  }
</style>
