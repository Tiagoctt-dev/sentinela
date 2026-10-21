import Button from "./Button";
import Modal from "./Modal";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirmar",
  danger = true,
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <Modal open={open} onClose={onCancel} title={title}>
      <p className="desc">{description}</p>
      <div className="modal-actions">
        <Button variant="ghost" onClick={onCancel} disabled={loading}>
          Cancelar
        </Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} loading={loading} loadingLabel="Excluindo…">
          {confirmLabel}
        </Button>
      </div>
    </Modal>
  );
}
