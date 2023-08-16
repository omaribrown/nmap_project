/** @type {import('./$types').PageServerLoad} */
export async function load() {
    return {};
};

/** @type {import('./$types').Actions} */
export const actions = {
    submit: async ({ request }) => {
        const formData = await request.formData();
        const ipsOrHostnames = formData.getAll('ip_or_hostname');
        const body = { ips_or_hostnames: ipsOrHostnames };
        const options = {
            headers: {
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: JSON.stringify(body),
        };
        const url = `http://localhost:8080/scan`;
        const response = await fetch(url, options);
        if (response.status !== 200) {
            let message = await response.json();
            console.log(message);
            return {
                success: false,
                message,
            };
        }
        const data = await response.json();
        console.log("data: ", data)
        let hostData = data.host;
        let scanResults = data.scan_results;
        let portHistory = data.port_history;
        let changes = data.changes;
        return {
            success: true,
            hostData,
            scanResults,
            portHistory,
            changes,
        };
    },
};