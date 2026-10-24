import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import app as pg
import re
def csrf_token(client, path="/"):
    response = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"No CSRF token found on {path}"
    return match.group(1).decode()

class JourneyTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); pg.DB=Path(self.tmp.name)/"test.db"; pg.init_db(); self.client=pg.app.test_client()
 def tearDown(self): self.tmp.cleanup()
 def test_home(self): self.assertEqual(self.client.get("/").status_code,200)
 def test_complete_lesson(self):
  self.assertEqual(self.client.post("/learn/lookalike/complete",data={"csrf_token":csrf_token(self.client,"/education")},follow_redirects=True).status_code,200)
  self.assertIn(b"Look-alike domains",self.client.get("/progress").data)
 def test_unknown_lesson(self): self.assertEqual(self.client.post("/learn/nope/complete",data={"csrf_token":csrf_token(self.client,"/education")}).status_code,302)
 def test_quiz_persists(self):
  data={f"q{i}":str(q["answer"]) for i,q in enumerate(pg.QUIZ)}; data["csrf_token"]=csrf_token(self.client,"/quiz"); r=self.client.post("/quiz",data=data)
  self.assertIn(b"Your score: 5/5",r.data); self.assertIn(b"5/5",self.client.get("/progress").data)
 def test_report_local_only(self):
  r=self.client.post("/report-phishing",data={"url":"example.com","details":"unexpected alert","csrf_token":csrf_token(self.client,"/report-phishing")}); self.assertIn(b"Report received",r.data)
  with pg.db() as con: row=con.execute("SELECT url,details FROM phishing_reports").fetchone()
  self.assertEqual(row["url"],"https://example.com"); self.assertEqual(row["details"],"unexpected alert")
 def test_report_rejects_bad_scheme(self): self.assertIn(b"valid HTTP or HTTPS",self.client.post("/report-phishing",data={"url":"javascript:alert(1)","csrf_token":csrf_token(self.client,"/report-phishing")}).data)
 def test_report_details_limit(self):
  self.client.post("/report-phishing",data={"url":"example.com","details":"x"*1200,"csrf_token":csrf_token(self.client,"/report-phishing")})
  with pg.db() as con: row=con.execute("SELECT details FROM phishing_reports").fetchone()
  self.assertEqual(len(row["details"]),1000)
if __name__=="__main__": unittest.main()

def test_email_simulation_page():
    client = pg.app.test_client()
    response = client.get("/email-simulation")
    assert response.status_code == 200
    assert b"Practice spotting suspicious emails" in response.data
    assert b"Three quick steps" in response.data
    assert b"simulation-layout" in response.data
    assert b"TRAINING INBOX" in response.data
    assert b"Example link (disabled for safety)" in response.data
    assert b"Example 1 of 3" in response.data
    assert b"Choose a practice email" in response.data

def test_email_simulation_can_select_each_scenario():
    client = pg.app.test_client()
    response = client.get("/email-simulation?scenario=routine")
    assert response.status_code == 200
    assert b"Your monthly statement is ready" in response.data
    assert b"Example 2 of 3" in response.data

def test_email_simulation_invalid_scenario_falls_back_to_first_example():
    response = pg.app.test_client().get("/email-simulation?scenario=unknown")
    assert response.status_code == 200
    assert b"Delivery address problem" in response.data
    assert b"Example 1 of 3" in response.data

def test_email_simulation_feedback_uses_selected_scenario():
    client = pg.app.test_client()
    token = csrf_token(client, "/email-simulation")
    response = client.post("/email-simulation", data={
        "csrf_token": token,
        "scenario_id": "delivery",
        "answer": "phishing",
    })
    assert response.status_code == 200
    assert b"That\xe2\x80\x99s right!" in response.data
    assert b"You chose: It looks suspicious." in response.data
    assert b"The best answer is It looks suspicious." in response.data
    assert b"Unexpected urgency" in response.data

def test_email_simulation_explains_incorrect_answer():
    client = pg.app.test_client()
    token = csrf_token(client, "/email-simulation")
    response = client.post("/email-simulation", data={
        "csrf_token": token,
        "scenario_id": "delivery",
        "answer": "safer",
    })
    assert response.status_code == 200
    assert b"Not quite\xe2\x80\x94here\xe2\x80\x99s what to notice" in response.data
    assert b"You chose: No obvious warning signs." in response.data
    assert b"The best answer is It looks suspicious." in response.data

def test_auth_pages_render_separate_labeled_fields():
    client = pg.app.test_client()
    login = client.get("/login")
    register = client.get("/register")
    assert login.status_code == register.status_code == 200
    assert b'class="auth-card"' in login.data
    assert b'for="email"' in login.data and b'for="password"' in login.data
    assert b"current-password" in login.data
    assert b"new-password" in register.data
    assert b"Use at least 12 characters." in register.data

def test_registration_and_admin_routes_exist():
    client = pg.app.test_client()
    assert client.get("/register").status_code == 200
    assert client.get("/login").status_code == 200
    # Non-authenticated users must not see the analyst console.
    response = client.get("/admin")
    assert response.status_code in (302, 401)

def test_versioned_training_api():
    client = pg.app.test_client()
    response = client.get("/api/v1/training/modules")
    assert response.status_code == 200
    assert b"lookalike" in response.data
