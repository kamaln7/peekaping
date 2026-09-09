import { GalleryVerticalEnd } from "lucide-react";
import { useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { LoginForm } from "./components/login-form";
import { useAuthStore } from "@/store/auth";
import { getConfig } from "@/lib/config";
import { useLocalizedTranslation } from "@/hooks/useTranslation";

export default function SHLoginPage() {
  const { t } = useLocalizedTranslation();
  const setTokens = useAuthStore((state) => state.setTokens);
  const setUser = useAuthStore((state) => state.setUser);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get("error");
    if (error) {
      toast.error(
        error === "oidc_not_admin"
          ? t("auth.oidc.not_admin")
          : t("auth.oidc.failed")
      );
      window.history.replaceState(null, "", window.location.pathname);
      return;
    }

    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const accessToken = hash.get("access_token");
    const refreshToken = hash.get("refresh_token");
    if (!accessToken || !refreshToken) {
      return;
    }

    // Drop the tokens from the address bar before doing anything with them.
    window.history.replaceState(null, "", window.location.pathname);

    // Raw request with the fresh token, like interceptors.ts does for refresh:
    // the persisted store stays untouched until we know the token works.
    axios
      .get(`${getConfig().API_URL}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      .then(({ data }) => {
        // Tokens and user are committed together: the sidebar (logout included)
        // stays hidden while user is null.
        setTokens(accessToken, refreshToken);
        setUser(data?.data ?? null);
        toast.success(t("messages.login_success"));
      })
      .catch(() => toast.error(t("auth.oidc.failed")));
  }, [setTokens, setUser, t]);

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <a href="#" className="flex items-center gap-2 self-center font-medium">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <GalleryVerticalEnd className="size-4" />
          </div>
          Peekaping
        </a>

        <LoginForm />
      </div>
    </div>
  );
}
