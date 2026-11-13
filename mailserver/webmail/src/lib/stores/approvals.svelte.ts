// ponytail: singleton for the pending-count rail badge; updated by ApprovalsApp on each poll
class ApprovalsCountStore {
	count = $state(0);
	set(n: number) { this.count = n; }
}
export const approvalsCount = new ApprovalsCountStore();
