/** @type {import('./$types').PageServerLoad} */
export async function load() {
    return {};
};

/** @type {import('./$types').Actions} */
export const actions = {
    submit: async ({ request })  => {
        const formData = await request.formData();

        const options = {
            headers: {
                'Content-Type': 'application/json',
            },
            method: 'POST',
            body: formData,
        }

        const url = `localhost:8080/scan`

        const response = await fetch(url, options);

        if (response.status !== 200) {
            return {
                success: false,
                message: response.statusText,
            }
        }
        const data = await response.json();
        
        return {
            success: true,
            data,
        }
    },
};