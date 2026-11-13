<script module lang="ts">
  // Named imports for tree-shaking. Add new icons here as needed.
  import AlignVerticalSpaceAround from 'lucide-svelte/icons/align-vertical-space-around';
  import AlertTriangle from 'lucide-svelte/icons/alert-triangle';
  import Archive from 'lucide-svelte/icons/archive';
  import ArrowLeft from 'lucide-svelte/icons/arrow-left';
  import ArrowLeftRight from 'lucide-svelte/icons/arrow-left-right';
  import Cloud from 'lucide-svelte/icons/cloud';
  import CloudOff from 'lucide-svelte/icons/cloud-off';
  import BarChart3 from 'lucide-svelte/icons/bar-chart-3';
  import Bell from 'lucide-svelte/icons/bell';
  import BellOff from 'lucide-svelte/icons/bell-off';
  import BellRing from 'lucide-svelte/icons/bell-ring';
  import Building2 from 'lucide-svelte/icons/building-2';
  import Boxes from 'lucide-svelte/icons/boxes';
  import CheckCircle2 from 'lucide-svelte/icons/check-circle-2';
  import CircleDashed from 'lucide-svelte/icons/circle-dashed';
  import HelpCircle from 'lucide-svelte/icons/help-circle';
  import KeyRound from 'lucide-svelte/icons/key-round';
  import MinusCircle from 'lucide-svelte/icons/minus-circle';
  import ShieldX from 'lucide-svelte/icons/shield-x';
  import UserMinus from 'lucide-svelte/icons/user-minus';
  import UserPlus from 'lucide-svelte/icons/user-plus';
  import FileSearch from 'lucide-svelte/icons/file-search';
  import ListFilter from 'lucide-svelte/icons/list-filter';
  import Gauge from 'lucide-svelte/icons/gauge';
  import MonitorSmartphone from 'lucide-svelte/icons/monitor-smartphone';
  import ToggleLeft from 'lucide-svelte/icons/toggle-left';
  import Bold from 'lucide-svelte/icons/bold';
  import Calendar from 'lucide-svelte/icons/calendar';
  import CalendarClock from 'lucide-svelte/icons/calendar-clock';
  import CalendarPlus from 'lucide-svelte/icons/calendar-plus';
  import CheckCheck from 'lucide-svelte/icons/check-check';
  import CheckCircle from 'lucide-svelte/icons/check-circle';
  import CheckSquare from 'lucide-svelte/icons/check-square';
  import ClipboardCheck from 'lucide-svelte/icons/clipboard-check';
  import ChevronDown from 'lucide-svelte/icons/chevron-down';
  import ChevronLeft from 'lucide-svelte/icons/chevron-left';
  import ChevronRight from 'lucide-svelte/icons/chevron-right';
  import ChevronUp from 'lucide-svelte/icons/chevron-up';
  import Clock from 'lucide-svelte/icons/clock';
  import Command from 'lucide-svelte/icons/command';
  import Cpu from 'lucide-svelte/icons/cpu';
  import DoorOpen from 'lucide-svelte/icons/door-open';
  import Download from 'lucide-svelte/icons/download';
  import Eye from 'lucide-svelte/icons/eye';
  import FileText from 'lucide-svelte/icons/file-text';
  import Folder from 'lucide-svelte/icons/folder';
  import Forward from 'lucide-svelte/icons/forward';
  import HardDrive from 'lucide-svelte/icons/hard-drive';
  import Inbox from 'lucide-svelte/icons/inbox';
  import Info from 'lucide-svelte/icons/info';
  import Italic from 'lucide-svelte/icons/italic';
  import Kanban from 'lucide-svelte/icons/kanban';
  import Key from 'lucide-svelte/icons/key';
  import Languages from 'lucide-svelte/icons/languages';
  import LayoutDashboard from 'lucide-svelte/icons/layout-dashboard';
  import LayoutGrid from 'lucide-svelte/icons/layout-grid';
  import Link from 'lucide-svelte/icons/link';
  import Lock from 'lucide-svelte/icons/lock';
  import List from 'lucide-svelte/icons/list';
  import ListChecks from 'lucide-svelte/icons/list-checks';
  import ListOrdered from 'lucide-svelte/icons/list-ordered';
  import LoaderCircle from 'lucide-svelte/icons/loader-circle';
  import LogOut from 'lucide-svelte/icons/log-out';
  import Mail from 'lucide-svelte/icons/mail';
  import Mic from 'lucide-svelte/icons/mic';
  import Square from 'lucide-svelte/icons/square';
  import MailCheck from 'lucide-svelte/icons/mail-check';
  import MailMinus from 'lucide-svelte/icons/mail-minus';
  import MapPin from 'lucide-svelte/icons/map-pin';
  import Maximize2 from 'lucide-svelte/icons/maximize-2';
  import Menu from 'lucide-svelte/icons/menu';
  import MessageCircle from 'lucide-svelte/icons/message-circle';
  import MessageSquare from 'lucide-svelte/icons/message-square';
  import Minimize2 from 'lucide-svelte/icons/minimize-2';
  import Minus from 'lucide-svelte/icons/minus';
  import Moon from 'lucide-svelte/icons/moon';
  import Newspaper from 'lucide-svelte/icons/newspaper';
  import Package from 'lucide-svelte/icons/package';
  import Palette from 'lucide-svelte/icons/palette';
  import PanelLeftClose from 'lucide-svelte/icons/panel-left-close';
  import PanelLeftOpen from 'lucide-svelte/icons/panel-left-open';
  import Paperclip from 'lucide-svelte/icons/paperclip';
  import PenLine from 'lucide-svelte/icons/pen-line';
  import Pencil from 'lucide-svelte/icons/pencil';
  import Plus from 'lucide-svelte/icons/plus';
  import PlusCircle from 'lucide-svelte/icons/plus-circle';
  import Printer from 'lucide-svelte/icons/printer';
  import Quote from 'lucide-svelte/icons/quote';
  import RefreshCw from 'lucide-svelte/icons/refresh-cw';
  import Reply from 'lucide-svelte/icons/reply';
  import ScrollText from 'lucide-svelte/icons/scroll-text';
  import Search from 'lucide-svelte/icons/search';
  import Send from 'lucide-svelte/icons/send';
  import ServerCog from 'lucide-svelte/icons/server-cog';
  import Settings from 'lucide-svelte/icons/settings';
  import Shield from 'lucide-svelte/icons/shield';
  import ShieldAlert from 'lucide-svelte/icons/shield-alert';
  import ShieldBan from 'lucide-svelte/icons/shield-ban';
  import ShieldCheck from 'lucide-svelte/icons/shield-check';
  import Sparkles from 'lucide-svelte/icons/sparkles';
  import SquareCheck from 'lucide-svelte/icons/square-check';
  import Star from 'lucide-svelte/icons/star';
  import Strikethrough from 'lucide-svelte/icons/strikethrough';
  import Share2 from 'lucide-svelte/icons/share-2';
  import Sun from 'lucide-svelte/icons/sun';
  import Trash2 from 'lucide-svelte/icons/trash-2';
  import TrendingUp from 'lucide-svelte/icons/trending-up';
  import Underline from 'lucide-svelte/icons/underline';
  import Users from 'lucide-svelte/icons/users';
  import Video from 'lucide-svelte/icons/video';
  import Wand2 from 'lucide-svelte/icons/wand-2';
  import X from 'lucide-svelte/icons/x';
  import XCircle from 'lucide-svelte/icons/x-circle';
  import Baseline from 'lucide-svelte/icons/baseline';
  import Image from 'lucide-svelte/icons/image';
  import PenTool from 'lucide-svelte/icons/pen-tool';
  import Undo2 from 'lucide-svelte/icons/undo-2';
  import ReplyAll from 'lucide-svelte/icons/reply-all';
  import MailOpen from 'lucide-svelte/icons/mail-open';
  import Copy from 'lucide-svelte/icons/copy';
  import Flag from 'lucide-svelte/icons/flag';
  import Globe from 'lucide-svelte/icons/globe';
  import MoreHorizontal from 'lucide-svelte/icons/more-horizontal';
  import Route from 'lucide-svelte/icons/route';
  import Zap from 'lucide-svelte/icons/zap';
  import Table from 'lucide-svelte/icons/table';
  import Rows3 from 'lucide-svelte/icons/rows-3';
  import Columns3 from 'lucide-svelte/icons/columns-3';
  import BetweenHorizontalEnd from 'lucide-svelte/icons/between-horizontal-end';
  import BetweenVerticalEnd from 'lucide-svelte/icons/between-vertical-end';
  import Fingerprint from 'lucide-svelte/icons/fingerprint';
  import UserCheck from 'lucide-svelte/icons/user-check';
  import Upload from 'lucide-svelte/icons/upload';
  import Pause from 'lucide-svelte/icons/pause';
  import GitBranch from 'lucide-svelte/icons/git-branch';
  import Unlock from 'lucide-svelte/icons/unlock';
  import History from 'lucide-svelte/icons/history';
  import Smile from 'lucide-svelte/icons/smile';
  import RotateCcw from 'lucide-svelte/icons/rotate-ccw';
  import Pin from 'lucide-svelte/icons/pin';
  import Bookmark from 'lucide-svelte/icons/bookmark';
  // Meet B1 Task 16 — in-meeting controls (mic/cam/screenshare toggles, leave, raise-hand)
  import MicOff from 'lucide-svelte/icons/mic-off';
  import VideoOff from 'lucide-svelte/icons/video-off';
  import ScreenShare from 'lucide-svelte/icons/screen-share';
  import ScreenShareOff from 'lucide-svelte/icons/screen-share-off';
  import Hand from 'lucide-svelte/icons/hand';
  import PhoneOff from 'lucide-svelte/icons/phone-off';
  // Meet B3 Task 15 — live captions toggle/chip
  import Captions from 'lucide-svelte/icons/captions';
  import CaptionsOff from 'lucide-svelte/icons/captions-off';


  const iconMap = {
    AlignVerticalSpaceAround, AlertTriangle, Archive, ArrowLeft, ArrowLeftRight, BarChart3, Baseline, Bell, BellOff, BellRing, Bold, Boxes, Building2, CheckCircle, CheckCircle2, CircleDashed, Cloud, CloudOff, Fingerprint,
    Calendar, CalendarClock, CalendarPlus, CheckCheck, CheckSquare, ClipboardCheck,
    ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Clock, Command, Cpu, DoorOpen, Download, Eye, FileSearch, FileText, Folder, Forward,
    Gauge, HardDrive, HelpCircle,
    Image, Inbox, Info, Italic, Kanban, Key, KeyRound, Languages, LayoutDashboard, LayoutGrid, Link, List, ListChecks, ListFilter, ListOrdered, LoaderCircle, Lock, LogOut,
    Copy, Flag, Globe, Mail, MailCheck, MailMinus, MailOpen, MapPin, Maximize2, Menu, MessageCircle, MessageSquare, Minimize2, Minus, MinusCircle, MonitorSmartphone, Moon, MoreHorizontal, Newspaper,
    Package, Palette, PanelLeftClose, PanelLeftOpen, Paperclip, PenLine, Pencil, PenTool, Plus, PlusCircle, Printer, Quote,
    RefreshCw, Reply, ReplyAll, Route, ScrollText, Search, Send, ServerCog, Settings, Shield, ShieldAlert, ShieldBan, ShieldCheck, Sparkles,
    Share2, ShieldX, SquareCheck, Star, Strikethrough, Sun, ToggleLeft, Trash2, TrendingUp, Underline, Undo2, UserCheck, UserMinus, UserPlus, Users, Video, Wand2, X, XCircle, Zap,
    Table, Rows3, Columns3, BetweenHorizontalEnd, BetweenVerticalEnd, Upload, Pause, GitBranch, Unlock, History, Smile, RotateCcw,
    Mic, Square, Pin, Bookmark,
    MicOff, VideoOff, ScreenShare, ScreenShareOff, Hand, PhoneOff,
    Captions, CaptionsOff,
  } as const;

  export type IconName = keyof typeof iconMap;
</script>

<script lang="ts">
  let { name, size = 20, class: cls = '', ...rest }: {
    name: IconName;
    size?: number;
    strokeWidth?: number;
    class?: string;
    [key: string]: unknown;
  } = $props();

  let IconComponent = $derived(iconMap[name]);
</script>

{#if IconComponent}
  <IconComponent {size} class={cls} {...rest} />
{/if}
