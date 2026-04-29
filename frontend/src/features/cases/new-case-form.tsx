import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { api } from "../../api/client";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";
import { Input } from "../../components/ui/input";

const initialState = {
  app_name: "",
  package_name: "",
  version_name: "",
  version_code: "",
  auditor: "",
  audit_date: new Date().toISOString().slice(0, 10),
  scope: "MASVS baseline evidence collection",
  notes: "",
};

export function NewCaseForm() {
  const [form, setForm] = useState(initialState);
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: api.createCase,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      setForm(initialState);
    },
  });

  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h3 className="font-display text-xl">New Audit Case</h3>
          <p className="text-sm text-slate-500">Capture audit scope and core metadata before evidence upload.</p>
        </div>
        <Button onClick={() => mutation.mutate(form)} disabled={mutation.isPending || !form.app_name || !form.auditor}>Create Case</Button>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {Object.entries(form).map(([key, value]) => (
          <label key={key} className="space-y-2 text-sm font-medium text-slate-600">
            {key.replace(/_/g, " ")}
            <Input value={value} onChange={(event) => setForm((current) => ({ ...current, [key]: event.target.value }))} />
          </label>
        ))}
      </div>
      {mutation.error ? <p className="mt-3 text-sm text-rose-600">{String(mutation.error)}</p> : null}
    </Card>
  );
}
