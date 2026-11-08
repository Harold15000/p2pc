# Security policy

P2PC runs workloads on people's computers, so we treat security reports as the highest priority.

## Reporting a vulnerability

- **Do not open a public issue.** Use GitHub's private vulnerability reporting: the repository's **Security** tab,
  then **Report a vulnerability**.
- Include:
  - the affected version or commit;
  - the component (agent, server, CLI, shim, SDK);
  - a description;
  - reproduction steps;
  - the impact you expect.
- **Response times:**
  - We acknowledge reports within 3 working days.
  - We aim to give an assessment within 10 working days.
  - We coordinate the disclosure with you, and credit you if you wish.

## In scope

- Escaping a job sandbox, or reaching the host, the LAN or a tailnet from a job.
- Bypassing authentication or access control: cross-account access, or using API keys or join tokens beyond their
  scope.
- Leaking secrets: keys, tokens or job environment values.
- Tricking a node into running a job it should refuse.
- Memory-safety or denial-of-service issues triggered by network input to the agent or the server.

## Supported versions

Before v1.0, only the latest release gets security fixes.
