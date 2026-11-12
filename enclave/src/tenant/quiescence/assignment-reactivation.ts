export interface AssignmentReactivationDeps {
  readonly releaseWork: (tenantId: string) => void;
  readonly isWorkHeld: (tenantId: string) => boolean;
  readonly finishWorkEviction: readonly ((tenantId: string) => void)[];
  readonly activate: (tenantId: string) => void;
}

/** Reopens a tenant for the assignment applier; queue-work eviction ends only when no holder remains. */
export function createAssignmentReactivation(
  deps: AssignmentReactivationDeps,
): (tenantId: string) => void {
  return (tenantId) => {
    deps.releaseWork(tenantId);
    if (!deps.isWorkHeld(tenantId)) {
      for (const finish of deps.finishWorkEviction) finish(tenantId);
    }
    deps.activate(tenantId);
  };
}
